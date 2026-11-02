// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/pins"
)

const marker = "LEAKED-BY-SERVER"

// reply is what the server answers to the request that carries token.
type reply struct {
	status  int // zero means 200
	file    string
	body    string
	header  map[string]string
	chunked bool // no Content-Length
	short   bool // promises more bytes than it sends
}

func fixture(file string) func(string) reply {
	return func(string) reply { return reply{file: file} }
}

// serve answers every POST with reply(page_token) and counts the requests.
func serve(t *testing.T, replies func(token string) reply) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		var q struct {
			Package   struct{ Ecosystem, Name string }
			Version   string
			PageToken string `json:"page_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil || r.Method != http.MethodPost ||
			r.Header.Get("Content-Type") != "application/json" ||
			q.Package.Ecosystem != "npm" || q.Package.Name != "fixture-pkg" || q.Version != "1.0.0" {
			t.Errorf("bad request: %s %v %+v", r.Method, err, q)
		}
		rp := replies(q.PageToken)
		body := []byte(rp.body)
		if rp.file != "" {
			var err error
			if body, err = os.ReadFile(filepath.Join("testdata", rp.file)); err != nil {
				t.Error(err)
			}
		}
		if !rp.chunked {
			n := len(body)
			if rp.short {
				n += 100
			}
			w.Header().Set("Content-Length", strconv.Itoa(n))
		}
		for k, v := range rp.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(max(rp.status, 200))
		w.Write(body)
		if f, ok := w.(http.Flusher); ok && rp.chunked {
			f.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

var testPin = pins.Pin{Name: "fixture-tool", Class: pins.Guest, Package: pins.Package{Ecosystem: "npm", Name: "fixture-pkg"}, Release: pins.Release{Version: "1.0.0"}}

func TestLookup(t *testing.T) {
	big := strings.Repeat("a", maxBody+1)
	noPackage := testPin
	noPackage.Package = pins.Package{}
	unstable := testPin
	unstable.Version = "1.0.0-rc.1"
	always := func(string) reply { return reply{body: `{"vulns":[],"next_page_token":"more"}`} }
	pages := func(tok string) reply {
		if tok == "" {
			return reply{file: "osv-page1.json"}
		}
		if tok == "page2" {
			return reply{file: "osv-page2.json"}
		}
		return reply{status: 400}
	}
	adv := func(id, from, fix string) *pins.Advisory { return &pins.Advisory{ID: id, Introduced: from, Fixed: fix} }

	tests := []struct {
		name     string
		pin      pins.Pin
		replies  func(string) reply
		plain    bool // use an http:// address
		cancel   bool
		wantErr  bool
		want     *pins.Advisory
		wantReqs int32
	}{
		// an advisory
		{"introduced 0 maps to an empty Introduced", testPin, fixture("osv-fix101.json"), false, false, false, adv("GHSA-aaaa-1111-0001", "", "1.0.1"), 1},
		{"two vulns: the highest fix and its id", testPin, fixture("osv-two.json"), false, false, false, adv("GHSA-bbbb-2222-0002", "", "1.2.0"), 1},
		{"versions list names the pin: the fix above it", testPin, fixture("osv-versions-list.json"), false, false, false, adv("GHSA-cccc-3333-0003", "", "2.0.5"), 1},
		{"two pages join: the highest fix wins", testPin, pages, false, false, false, adv("GHSA-dddd-4444-0004", "1.0.0", "1.1.0"), 2},
		// no advisory
		{"empty vulns", testPin, fixture("osv-empty.json"), false, false, false, nil, 1},
		{"withdrawn vuln", testPin, fixture("osv-withdrawn.json"), false, false, false, nil, 1},
		{"same name in another ecosystem", testPin, fixture("osv-other-ecosystem.json"), false, false, false, nil, 1},
		{"same name in another case", testPin, fixture("osv-other-name.json"), false, false, false, nil, 1},
		{"range does not contain the version", testPin, fixture("osv-out-of-range.json"), false, false, false, nil, 1},
		{"introduced 0 with the version above the fix", testPin, fixture("osv-above-fixed.json"), false, false, false, nil, 1},
		{"git-only range", testPin, fixture("osv-git-only.json"), false, false, false, nil, 1},
		{"last_affected without a fix", testPin, fixture("osv-last-affected.json"), false, false, false, nil, 1},
		{"fix is a pre-release", testPin, fixture("osv-prerelease.json"), false, false, false, nil, 1},
		{"pin without a package asks nothing", noPackage, fixture("osv-fix101.json"), false, false, false, nil, 0},
		{"pin without a stable version asks nothing", unstable, fixture("osv-fix101.json"), false, false, false, nil, 0},
		// the database cannot be consulted
		{"status 500", testPin, func(string) reply { return reply{status: 500, body: marker} }, false, false, true, nil, 1},
		{"status 404", testPin, func(string) reply { return reply{status: 404, body: marker} }, false, false, true, nil, 1},
		{"malformed JSON", testPin, func(string) reply { return reply{body: `{"vulns":` + marker} }, false, false, true, nil, 1},
		{"truncated body", testPin, func(string) reply { return reply{body: `{"vulns":[`, short: true} }, false, false, true, nil, 1},
		{"empty 200 body", testPin, func(string) reply { return reply{} }, false, false, true, nil, 1},
		{"over the cap by Content-Length", testPin, func(string) reply {
			return reply{body: marker, header: map[string]string{"Content-Length": strconv.Itoa(maxBody + 1)}}
		}, false, false, true, nil, 1},
		{"over the cap while reading", testPin, func(string) reply { return reply{body: big, chunked: true} }, false, false, true, nil, 1},
		{"redirect to https", testPin, func(string) reply {
			return reply{status: 301, header: map[string]string{"Location": "https://example.test/" + marker}}
		}, false, false, true, nil, 1},
		{"redirect to http", testPin, func(string) reply {
			return reply{status: 301, header: map[string]string{"Location": "http://example.test/" + marker}}
		}, false, false, true, nil, 1},
		{"plain http address", testPin, fixture("osv-fix101.json"), true, false, true, nil, 0},
		{"context already cancelled", testPin, fixture("osv-fix101.json"), false, true, true, nil, -1},
		{"a ninth page", testPin, always, false, false, true, nil, maxPages},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, n := serve(t, tt.replies)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			db := srv.URL + "/v1/query"
			if tt.plain {
				db = strings.Replace(db, "https://", "http://", 1)
			}
			got, err := Lookup(ctx, srv.Client(), db, tt.pin)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if err != nil && (!strings.Contains(err.Error(), tt.pin.Name) || strings.Contains(err.Error(), marker)) {
				t.Errorf("error %q must name the pin and echo nothing the server sent", err)
			}
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Errorf("advisory = %+v, want %+v", got, tt.want)
			}
			if tt.wantReqs >= 0 && n.Load() != tt.wantReqs {
				t.Errorf("%d requests, want %d", n.Load(), tt.wantReqs)
			}
		})
	}
}

// TestSecurityLane runs the fixture advisory into the selector (B4, W8).
func TestSecurityLane(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	cand := func(age time.Duration) []pins.Candidate {
		return []pins.Candidate{{Release: pins.Release{Version: "1.0.1"}, Timestamps: []time.Time{now.Add(-age)}}}
	}
	trusted := testPin
	trusted.Class = pins.Trusted
	tests := []struct {
		name         string
		pin          pins.Pin
		replies      func(string) reply
		age          time.Duration
		lookupErr    bool
		want         string
		security, am bool
	}{
		{"advisory: guest 12h chooses the fix and auto-merges", testPin, fixture("osv-fix101.json"), 12 * time.Hour, false, "1.0.1", true, true},
		{"advisory: trusted at once, waits for the maintainer", trusted, fixture("osv-fix101.json"), 0, false, "1.0.1", true, false},
		{"lookup error: guest 12h is still cooling off", testPin, func(string) reply { return reply{status: 500} }, 12 * time.Hour, true, "", false, false},
		{"lookup error: guest 48h takes the normal path", testPin, func(string) reply { return reply{status: 500} }, 48 * time.Hour, true, "1.0.1", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := serve(t, tt.replies)
			adv, err := Lookup(t.Context(), srv.Client(), srv.URL, tt.pin) // an error leaves adv nil
			if (err != nil) != tt.lookupErr || (err != nil && adv != nil) {
				t.Fatalf("adv = %+v, err = %v, want error %v", adv, err, tt.lookupErr)
			}
			r, err := pins.Select(tt.pin, cand(tt.age), adv, 0, now)
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if r.Chosen != nil {
				got = r.Chosen.Version
			}
			if got != tt.want || r.Security != tt.security || (got != "" && r.AutoMerge != tt.am) {
				t.Errorf("chose %q security %v auto-merge %v, want %q %v %v", got, r.Security, r.AutoMerge, tt.want, tt.security, tt.am)
			}
		})
	}
}

// FuzzAnswer feeds the response parser and the mapper arbitrary bytes.
func FuzzAnswer(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	for _, name := range files {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b)
		}
	}
	cur, _ := parseVersion(testPin.Version)
	f.Fuzz(func(t *testing.T, data []byte) {
		var a answer
		if json.Unmarshal(data, &a) != nil {
			return
		}
		for _, v := range a.Vulns {
			adv, fix, ok := v.match(testPin, cur)
			if !ok {
				continue
			}
			from, fromOK := parseVersion(adv.Introduced)
			if got, fixOK := parseVersion(adv.Fixed); !fixOK || got != fix || compare(cur, fix) >= 0 ||
				(adv.Introduced != "" && (!fromOK || compare(from, cur) > 0)) {
				t.Fatalf("match returned %+v for %s", adv, testPin.Version)
			}
		}
	})
}
