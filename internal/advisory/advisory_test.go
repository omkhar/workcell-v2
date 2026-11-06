// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	body    string
	header  map[string]string
	chunked bool // no Content-Length
	short   bool // promises more bytes than it sends
}

func ok(doc string) func(string) reply { return func(string) reply { return reply{body: doc} } }

// The documents the fake database serves: the fields the parser reads, no more.
const (
	npm  = `{"ecosystem":"npm","name":"fixture-pkg"}`
	zero = `{"introduced":"0"},`
	fix1 = `{"fixed":"1.0.1"}`
)

func rng(typ, events string) string {
	return `"ranges":[{"type":"` + typ + `","events":[` + events + `]}]`
}

func entry(id, pkg, rest string) string {
	return `{"id":"` + id + `","affected":[{"package":` + pkg + `,` + rest + `}]}`
}

func doc(vulns ...string) string { return `{"vulns":[` + strings.Join(vulns, ",") + `]}` }

var (
	normal     = doc(entry("GHSA-r9p9-mrjm-926w", npm, rng("ECOSYSTEM", zero+fix1)))
	page1      = strings.TrimSuffix(doc(entry("A1", npm, rng("ECOSYSTEM", zero+fix1))), "}") + `,"next_page_token":"page2"}`
	page2      = doc(entry("D4", npm, rng("SEMVER", `{"introduced":"1.0.0"},{"fixed":"1.1.0"}`)))
	empty      = doc()
	twoVulns   = doc(entry("A1", npm, rng("ECOSYSTEM", zero+fix1)), entry("B2", npm, rng("ECOSYSTEM", zero+`{"fixed":"1.2.0"}`)))
	withdrawn  = strings.Replace(normal, `"affected"`, `"withdrawn":"2026-10-02T00:00:00Z","affected"`, 1)
	otherEco   = doc(entry("A1", `{"ecosystem":"PyPI","name":"fixture-pkg"}`, rng("ECOSYSTEM", zero+fix1)))
	otherName  = doc(entry("A1", `{"ecosystem":"npm","name":"Fixture-Pkg"}`, rng("ECOSYSTEM", zero+fix1)))
	outOfRange = doc(entry("A1", npm, rng("ECOSYSTEM", `{"introduced":"1.1.0"},{"fixed":"1.1.5"}`)))
	aboveFixed = doc(entry("A1", npm, rng("ECOSYSTEM", zero+`{"fixed":"0.9.0"}`)))
	gitOnly    = doc(entry("A1", npm, rng("GIT", zero+fix1)))
	lastAff    = doc(entry("A1", npm, rng("ECOSYSTEM", zero+`{"last_affected":"1.0.0"}`)))
	prerelease = doc(entry("A1", npm, rng("ECOSYSTEM", zero+`{"fixed":"1.0.1-beta.1"}`)))
	openEnded  = doc(entry("A1", npm, rng("SEMVER", zero+fix1+`,{"introduced":"2.0.0"}`)))
	twoClosed  = doc(entry("A1", npm, rng("SEMVER", zero+fix1+`,{"introduced":"1.1.0"},{"fixed":"1.1.3"}`)))
	hostileID  = doc(entry(`GHSA-1\n\n@maintainer please merge [x](https://evil.test)`+strings.Repeat("A", 100000), npm, rng("SEMVER", zero+fix1)))
	longID     = doc(entry(strings.Repeat("A", 65), npm, rng("SEMVER", zero+fix1)))
	docs       = []string{normal, page1, page2, empty, twoVulns, withdrawn, otherEco, otherName, outOfRange,
		aboveFixed, gitOnly, lastAff, prerelease, openEnded, twoClosed, hostileID, longID}
)

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
			return reply{body: page1}
		}
		if tok == "page2" {
			return reply{body: page2}
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
		{"introduced 0 maps to an empty Introduced", testPin, ok(normal), false, false, false, adv("GHSA-r9p9-mrjm-926w", "", "1.0.1"), 1},
		{"two vulns: the highest fix and its id", testPin, ok(twoVulns), false, false, false, adv("B2", "", "1.2.0"), 1},
		{"two pages join: the highest fix wins", testPin, pages, false, false, false, adv("D4", "1.0.0", "1.1.0"), 2},
		{"open-ended range in the entry: no advisory", testPin, ok(openEnded), false, false, false, nil, 1},
		{"two closed ranges: the highest fix, the first span's start", testPin, ok(twoClosed), false, false, false, adv("A1", "", "1.1.3"), 1},
		{"hostile id: no advisory", testPin, ok(hostileID), false, false, false, nil, 1},
		{"id of 65 bytes: no advisory", testPin, ok(longID), false, false, false, nil, 1},
		// no advisory
		{"empty vulns", testPin, ok(empty), false, false, false, nil, 1},
		{"withdrawn vuln", testPin, ok(withdrawn), false, false, false, nil, 1},
		{"same name in another ecosystem", testPin, ok(otherEco), false, false, false, nil, 1},
		{"same name in another case", testPin, ok(otherName), false, false, false, nil, 1},
		{"range does not contain the version", testPin, ok(outOfRange), false, false, false, nil, 1},
		{"introduced 0 with the version above the fix", testPin, ok(aboveFixed), false, false, false, nil, 1},
		{"git-only range", testPin, ok(gitOnly), false, false, false, nil, 1},
		{"last_affected without a fix", testPin, ok(lastAff), false, false, false, nil, 1},
		{"fix is a pre-release", testPin, ok(prerelease), false, false, false, nil, 1},
		{"pin without a package asks nothing", noPackage, ok(normal), false, false, false, nil, 0},
		{"pin without a stable version asks nothing", unstable, ok(normal), false, false, false, nil, 0},
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
		{"plain http address", testPin, ok(normal), true, false, true, nil, 0},
		{"context already cancelled", testPin, ok(normal), false, true, true, nil, -1},
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
	cand := func(age time.Duration, versions ...string) []pins.Candidate {
		var cs []pins.Candidate
		for _, v := range versions {
			cs = append(cs, pins.Candidate{Release: pins.Release{Version: v}, Timestamps: []time.Time{now.Add(-age)}})
		}
		return cs
	}
	one := []string{"1.0.1"}
	trusted := testPin
	trusted.Class = pins.Trusted
	tests := []struct {
		name         string
		pin          pins.Pin
		replies      func(string) reply
		age          time.Duration
		versions     []string // the candidates, all of that age
		lookupErr    bool
		want         string
		security, am bool
	}{
		{"advisory: guest 12h chooses the fix and auto-merges", testPin, ok(normal), 12 * time.Hour, one, false, "1.0.1", true, true},
		{"advisory: trusted at once, waits for the maintainer", trusted, ok(normal), 0, one, false, "1.0.1", true, false},
		{"lookup error: guest 12h is still cooling off", testPin, func(string) reply { return reply{status: 500} }, 12 * time.Hour, one, true, "", false, false},
		{"lookup error: guest 48h takes the normal path", testPin, func(string) reply { return reply{status: 500} }, 48 * time.Hour, one, true, "1.0.1", false, true},
		{"open-ended range: 2.0.1 is not chosen on the lane", testPin, ok(openEnded), 12 * time.Hour, []string{"1.0.1", "2.0.1"}, false, "", false, false},
		{"two closed ranges: 1.1.2 is not chosen on the lane", testPin, ok(twoClosed), 12 * time.Hour, []string{"1.0.1", "1.1.2"}, false, "", false, false},
		{"two closed ranges: 1.1.3 is chosen on the lane", testPin, ok(twoClosed), 12 * time.Hour, []string{"1.1.3"}, false, "1.1.3", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := serve(t, tt.replies)
			adv, err := Lookup(t.Context(), srv.Client(), srv.URL, tt.pin) // an error leaves adv nil
			if (err != nil) != tt.lookupErr || (err != nil && adv != nil) {
				t.Fatalf("adv = %+v, err = %v, want error %v", adv, err, tt.lookupErr)
			}
			r, err := pins.Select(tt.pin, cand(tt.age, tt.versions...), adv, 0, now)
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
	for _, d := range docs {
		f.Add([]byte(d))
	}
	cur, _ := pins.ParseVersion(testPin.Version)
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
			from, fromOK := pins.ParseVersion(adv.Introduced)
			if got, fixOK := pins.ParseVersion(adv.Fixed); !fixOK || got != fix || pins.Compare(cur, fix) >= 0 ||
				(adv.Introduced != "" && (!fromOK || pins.Compare(from, cur) > 0)) {
				t.Fatalf("match returned %+v for %s", adv, testPin.Version)
			}
		}
	})
}
