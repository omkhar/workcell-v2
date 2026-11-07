// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/bump"
	"github.com/omkhar/workcell/v2/internal/pins"
)

var (
	now   = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	head  = strings.Repeat("ab", 20)
	token = "tok-do-not-print"
)

// drip is an upstream body sent one byte at a time after the headers, for ten seconds, far past the planning time of a pin.
const drip = "\x00drip"

type reply struct {
	status int
	body   string
	link   string // a Link header; {api} stands for the stand-in's URL
	slow   bool   // answer after the client gave up
}

type call struct{ method, uri, body string }

// standIn is GitHub's REST API for repository o/r: routes keyed "METHOD /uri". A write that has no route answers 201 and pull request number 7.
type standIn struct {
	mu     sync.Mutex
	routes map[string]reply
	calls  []call
}

func (s *standIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.calls = append(s.calls, call{r.Method, r.URL.RequestURI(), string(b)})
	rp, ok := s.routes[r.Method+" "+r.URL.RequestURI()]
	s.mu.Unlock()
	switch {
	case !ok && r.Method != http.MethodGet:
		rp = reply{status: 201, body: `{"number": 7}`}
	case !ok:
		rp = reply{status: 404, body: `{"message": "Not Found"}`}
	}
	if rp.slow {
		time.Sleep(time.Second)
	}
	if rp.link != "" {
		w.Header().Set("Link", strings.ReplaceAll(rp.link, "{api}", "http://"+r.Host))
	}
	w.WriteHeader(max(rp.status, 200))
	io.WriteString(w, rp.body)
}

// writes lists every request that is not a GET.
func (s *standIn) writes() []call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(s.calls), func(c call) bool { return c.method == http.MethodGet })
}

type fixture struct {
	pins     []pins.Pin
	extra    map[string]string // more files in the pins directory
	upstream map[string]string // path to body; "/osv" answers the advisory query
	routes   map[string]reply
	args     []string // more flags
}

// release records a vendor-manifest release of name under /name; a wrong digest publishes a checksum that is not the artifact's.
func release(f *fixture, name, version string, built time.Time, wrongDigest bool) {
	art := "artifact of " + name + " " + version
	sum := sha256.Sum256([]byte(art))
	if wrongDigest {
		sum = sha256.Sum256([]byte("something else"))
	}
	root := "/" + name + "/"
	f.upstream[root+"latest"] = version + "\n"
	f.upstream[root+version+"/manifest.json"] = fmt.Sprintf(`{"version":%q,"buildDate":%q,"platforms":{"linux-x64":{"checksum":%q,"binary":%q}}}`,
		version, built.Format(time.RFC3339), hex.EncodeToString(sum[:]), name)
	f.upstream[root+version+"/linux-x64/"+name] = art
}

func pin(name string, class pins.Class, version string) pins.Pin {
	return pins.Pin{Name: name, Class: class, Source: pins.VendorManifest, Assets: map[string]string{"amd64": "linux-x64"},
		Release: pins.Release{Version: version, Artifacts: map[string]pins.Artifact{"amd64": {SHA256: strings.Repeat("0", 64)}}}}
}

func pullJSON(n int, ref, repo string, fork bool, changed int, labels ...string) string {
	ls := []map[string]string{}
	for _, l := range labels {
		ls = append(ls, map[string]string{"name": l})
	}
	b, _ := json.Marshal(map[string]any{"number": n, "changed_files": changed, "labels": ls, "base": map[string]string{"ref": "main"},
		"head": map[string]any{"ref": ref, "sha": head, "repo": map[string]any{"full_name": repo, "fork": fork}}})
	return string(b)
}

func checks(runs ...string) string {
	return fmt.Sprintf(`{"total_count": %d, "check_runs": [%s]}`, len(runs), strings.Join(runs, ","))
}

func checkRun(name, status, conclusion string) string {
	return fmt.Sprintf(`{"name":%q,"status":%q,"conclusion":%q,"head_sha":%q}`, name, status, conclusion, head)
}

const (
	listPRs  = "GET /repos/o/r/pulls?state=open&base=main&per_page=100"
	files5   = "GET /repos/o/r/pulls/5/files?per_page=100"
	checks5  = "GET /repos/o/r/commits/" + "abababababababababababababababababababab" + "/check-runs?per_page=100"
	merge5   = "PUT /repos/o/r/pulls/5/merge"
	rowPatch = `[{"filename":"pins/tool.json","status":"modified","patch":"@@ -16 +16 @@\n-  \"Version\": \"1.2.0\",\n+  \"Version\": \"1.3.0\","}]`
)

// openTrusted records open trusted bump pull request 5 with the labels, one row changed and a green gate.
func openTrusted(f *fixture, labels ...string) {
	openGuest(f)
	f.routes[listPRs] = reply{body: "[" + pullJSON(5, "bump/trusted-20261119", "o/r", false, 1, labels...) + "]"}
	f.routes["GET /repos/o/r/pulls/5"] = reply{body: pullJSON(5, "bump/trusted-20261119", "o/r", false, 1, labels...)}
}

// openGuest records open guest bump pull request 5 with one row changed and a green gate.
func openGuest(f *fixture) {
	f.routes[listPRs] = reply{body: "[" + pullJSON(5, "bump/guest-20261119", "o/r", false, 1) + "]"}
	f.routes["GET /repos/o/r/pulls/5"] = reply{body: pullJSON(5, "bump/guest-20261119", "o/r", false, 1)}
	f.routes[files5] = reply{body: rowPatch}
	f.routes[checks5] = reply{body: checks(checkRun("gate", "completed", "success"), checkRun("guard", "completed", "success"))}
}

func w(method, uri string) call { return call{method: method, uri: uri} }

var (
	openGuestPR   = []call{w("POST", "/repos/o/r/git/refs"), w("PUT", "/repos/o/r/contents/pins/tool.json"), w("POST", "/repos/o/r/pulls")}
	openTrustedPR = []call{w("POST", "/repos/o/r/git/refs"), w("PUT", "/repos/o/r/contents/pins/kit.json"), w("POST", "/repos/o/r/pulls")}
	mergeOnce     = []call{w("PUT", "/repos/o/r/pulls/5/merge")}
)

type runCase struct {
	name   string
	dry    bool
	edit   func(*fixture)
	code   int
	out    []string // lines the output holds
	writes []call   // every write, in order, compared by method and URI
	check  func(*testing.T, []call)
}

func TestRun(t *testing.T) {
	cases := []runCase{
		{name: "dry run plans, posts nothing", dry: true, code: 0,
			out: []string{"dry-run: nothing is posted or written", "kit trusted 2.0.0 2.1.0 eligible", "tool guest 1.2.0 1.3.0 eligible",
				"would open pull request: guest", "would open pull request: trusted"}},
		{name: "one pull request per class", code: 0, out: []string{"opened pull request: guest 7", "opened pull request: trusted 7"},
			writes: slices.Concat(openGuestPR, openTrustedPR), check: checkOpened},
		{name: "guest already open and green: merged once with the checked head, no second guest pull request", code: 0, edit: openGuest,
			out: []string{"merged: 5", "already open: guest", "opened pull request: trusted 7"}, writes: slices.Concat(mergeOnce, openTrustedPR),
			check: func(t *testing.T, cs []call) {
				if !strings.Contains(cs[0].body, `"sha":"`+head+`"`) || !strings.Contains(cs[0].body, `"merge_method":"squash"`) {
					t.Errorf("merge body %s", cs[0].body)
				}
			}},
		{name: "dry run: would merge the green pull request", dry: true, code: 0, edit: openGuest, out: []string{"would merge: 5", "already open: guest"}},
		{name: "a changed path outside pins is refused, never merged", code: 2, edit: func(f *fixture) {
			openGuest(f)
			f.routes[files5] = reply{body: `[{"filename":"pins/tool.json","status":"modified","patch":"@@ -1 +1 @@\n+x"},{"filename":".github/workflows/ci.yml","status":"modified","patch":"@@ -1 +1 @@\n+x"}]`}
			f.routes["GET /repos/o/r/pulls/5"] = reply{body: pullJSON(5, "bump/guest-20261119", "o/r", false, 2)}
		}},
		{name: "page two of the changed files leaves pins: refused", code: 2, edit: func(f *fixture) {
			openGuest(f)
			f.routes["GET /repos/o/r/pulls/5"] = reply{body: pullJSON(5, "bump/guest-20261119", "o/r", false, 2)}
			f.routes[files5] = reply{body: rowPatch, link: `<{api}/repos/o/r/pulls/5/files?per_page=100&page=2>; rel="next"`}
			f.routes[strings.TrimSuffix(files5, "100")+"100&page=2"] = reply{body: `[{"filename":".github/x","status":"added","patch":"@@ -0,0 +1 @@\n+{"}]`}
		}},
		{name: "page two of the changed files fails: stopped", code: 1, edit: func(f *fixture) {
			openGuest(f)
			f.routes[files5] = reply{body: rowPatch, link: `<{api}/repos/o/r/pulls/5/files?per_page=100&page=2>; rel="next"`}
			f.routes[strings.TrimSuffix(files5, "100")+"100&page=2"] = reply{status: 500}
		}},
		{name: "changed_files above the listed entries: refused", code: 2, edit: func(f *fixture) {
			openGuest(f)
			f.routes["GET /repos/o/r/pulls/5"] = reply{body: pullJSON(5, "bump/guest-20261119", "o/r", false, 3)}
		}},
		{name: "the merge waits for a green gate", code: 0, out: []string{"waits for gate: 5", "already open: guest"}, writes: openTrustedPR,
			edit: func(f *fixture) {
				openGuest(f)
				f.routes[checks5] = reply{body: checks(checkRun("gate", "in_progress", ""), checkRun("guard", "completed", "success"))}
			}},
		{name: "only gate-macos is green: no merge", code: 0, out: []string{"waits for gate: 5"}, writes: openTrustedPR, edit: func(f *fixture) {
			openGuest(f)
			f.routes[checks5] = reply{body: checks(checkRun("gate-macos", "completed", "success"))}
		}},
		{name: "the merge answers 409: stopped after one call", code: 1, writes: mergeOnce, edit: func(f *fixture) {
			openGuest(f)
			f.routes[merge5] = reply{status: 409, body: `{"message":"Head branch was modified"}`}
		}},
		{name: "the merge answers 405: stopped after one call", code: 1, writes: mergeOnce, edit: func(f *fixture) {
			openGuest(f)
			f.routes[merge5] = reply{status: 405}
		}},
		{name: "a guest security pull request merges once the gate is green", code: 0, out: []string{"merged: 5"},
			writes: slices.Concat(mergeOnce, openTrustedPR), edit: func(f *fixture) {
				openGuest(f)
				f.routes["GET /repos/o/r/pulls/5"] = reply{body: pullJSON(5, "bump/guest-20261119", "o/r", false, 1, "security")}
			}},
		{name: "a trusted security pull request is never merged by the tool", code: 0,
			out: []string{"waits for the maintainer: 5", "already open: trusted"}, writes: openGuestPR,
			edit: func(f *fixture) { openTrusted(f, "security") }},
		{name: "a trusted security note in the body without the label: never merged", code: 0, out: []string{"waits for the maintainer: 5"},
			writes: openGuestPR, edit: func(f *fixture) {
				openTrusted(f)
				f.routes["GET /repos/o/r/pulls/5"] = reply{body: strings.Replace(pullJSON(5, "bump/trusted-20261119", "o/r", false, 1),
					`"number":5`, `"body":"- x: 1.0.0 to 1.1.0, age 1h, security: an advisory affects the pinned version and this release fixes it\n","number":5`, 1)}
			}},
		{name: "a fork's bump branch is neither merged nor counted", code: 0, writes: slices.Concat(openGuestPR, openTrustedPR), edit: func(f *fixture) {
			openGuest(f)
			f.routes[listPRs] = reply{body: "[" + pullJSON(5, "bump/guest-20261119", "evil/r", true, 1) + "]"}
		}},
		{name: "list pull requests fails: stopped, nothing opened", code: 1, edit: func(f *fixture) { f.routes[listPRs] = reply{status: 500} }},
		{name: "list pull requests answers HTML: stopped", code: 1, edit: func(f *fixture) { f.routes[listPRs] = reply{body: "<html>hi</html>"} }},
		{name: "list pull requests times out: stopped", code: 1, edit: func(f *fixture) { f.routes[listPRs] = reply{slow: true, body: "[]"} }},
		{name: "check runs fail: stopped, no merge", code: 1, edit: func(f *fixture) { openGuest(f); f.routes[checks5] = reply{status: 500} }},
		{name: "verification fails: one issue, no pull request, no older release", code: 0,
			out: []string{"tool guest 1.2.0 1.3.0 verify-failed", "opened issue: tool"}, writes: []call{w("POST", "/repos/o/r/issues")},
			edit: func(f *fixture) { f.pins = f.pins[1:]; release(f, "tool", "1.3.0", now.Add(-120*time.Hour), true) }},
		{name: "verification fails, its issue is open: no second issue", code: 0, writes: nil, edit: func(f *fixture) {
			f.pins = f.pins[1:]
			release(f, "tool", "1.3.0", now.Add(-120*time.Hour), true)
			f.routes["GET /repos/o/r/issues?state=open&per_page=100"] = reply{body: `[{"title":"bump: verification failed: tool"}]`}
		}},
		{name: "dry run: would open issue", dry: true, code: 0, out: []string{"would open issue: tool"},
			edit: func(f *fixture) { f.pins = f.pins[1:]; release(f, "tool", "1.3.0", now.Add(-120*time.Hour), true) }},
		{name: "the newest release is the pinned one: no change", code: 0, out: []string{"tool guest 1.3.0 none backwards"},
			edit: func(f *fixture) { f.pins = f.pins[1:]; f.pins[0].Version = "1.3.0" }},
		{name: "trusted with an advisory opens at once, labelled security", code: 0,
			out:    []string{"kit trusted 2.0.0 2.1.0 eligible", "opened pull request: trusted 7"},
			writes: slices.Concat(openTrustedPR, []call{w("POST", "/repos/o/r/issues/7/labels")}), check: securityNote(true),
			edit: func(f *fixture) {
				f.pins = f.pins[:1]
				f.pins[0].Package = pins.Package{Ecosystem: "npm", Name: "kit"}
				release(f, "kit", "2.1.0", now.Add(-time.Hour), false)
				f.upstream["/osv"] = `{"vulns":[{"id":"GHSA-1","affected":[{"package":{"ecosystem":"npm","name":"kit"},` +
					`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.1.0"}]}]}]}]}`
			}},
		{name: "guest with an advisory, released 6 hours ago: no pull request", code: 0, out: []string{"tool guest 1.2.0 none cool-off"},
			edit: func(f *fixture) {
				f.pins = f.pins[1:]
				f.pins[0].Package = pins.Package{Ecosystem: "npm", Name: "tool"}
				release(f, "tool", "1.3.0", now.Add(-6*time.Hour), false)
				f.upstream["/osv"] = `{"vulns":[{"id":"GHSA-2","affected":[{"package":{"ecosystem":"npm","name":"tool"},` +
					`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.3.0"}]}]}]}]}`
			}},
		{name: "guest with an advisory, past its cool-off: no security note, no label", code: 0,
			out: []string{"tool guest 1.2.0 1.3.0 eligible", "opened pull request: guest 7"}, writes: openGuestPR, check: securityNote(false),
			edit: func(f *fixture) {
				f.pins = f.pins[1:]
				f.pins[0].Package = pins.Package{Ecosystem: "npm", Name: "tool"}
				f.upstream["/osv"] = `{"vulns":[{"id":"GHSA-3","affected":[{"package":{"ecosystem":"npm","name":"tool"},` +
					`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.3.0"}]}]}]}]}`
			}},
		{name: "one upstream drips its artifact: that pin fails, the next is planned", code: 0,
			out:    []string{"kit trusted 2.0.0 2.1.0 verify-failed", "tool guest 1.2.0 1.3.0 eligible", "opened issue: kit", "opened pull request: guest 7"},
			writes: slices.Concat([]call{w("POST", "/repos/o/r/issues")}, openGuestPR),
			edit:   func(f *fixture) { f.upstream["/kit/2.1.0/linux-x64/kit"] = drip }},
	}
	for _, name := range []string{"../.github/workflows/x", "pins/../x", "/etc/x", `..\x`, "a/b", ".x", "", "x\x00", "x\ny", "UP", strings.Repeat("a", 65)} {
		cases = append(cases, runCase{name: "pin name " + name, code: 2, edit: func(f *fixture) { f.extra["x.json"] = string(bump.Row(pin(name, pins.Guest, "1.0.0"))) }})
	}
	cases = append(cases,
		runCase{name: "a case twin of a row", code: 2, edit: func(f *fixture) { f.extra["Tool.json"] = string(bump.Row(pin("Tool", pins.Guest, "1.0.0"))) }},
		runCase{name: "a file outside the name grammar", code: 2, edit: func(f *fixture) { f.extra[".x.json"] = "{}" }},
		runCase{name: "a file that is not a row", code: 2, edit: func(f *fixture) { f.extra["notes.txt"] = "x" }},
		runCase{name: "a Go file beside the rows is skipped", code: 0, writes: slices.Concat(openGuestPR, openTrustedPR), edit: func(f *fixture) { f.extra["pins_test.go"] = "x" }},
		runCase{name: "class Guest", code: 2, edit: func(f *fixture) { f.pins[1].Class = "Guest" }},
		runCase{name: "class empty", code: 2, edit: func(f *fixture) { f.pins[1].Class = "" }},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture()
			if tc.edit != nil {
				tc.edit(&f)
			}
			start := time.Now()
			out, code, api, before, after := runFixture(t, f, tc.dry)
			if d := time.Since(start); d > 6*time.Second {
				t.Errorf("the run took %v", d)
			}
			if code != tc.code {
				t.Errorf("exit %d, want %d; output:\n%s", code, tc.code, out)
			}
			for _, l := range tc.out {
				if !slices.Contains(strings.Split(out, "\n"), l) {
					t.Errorf("output lacks %q:\n%s", l, out)
				}
			}
			for _, bad := range []string{token, "http", "artifact of", "GHSA", "Not Found", "modified"} {
				if strings.Contains(out, bad) {
					t.Errorf("output holds %q:\n%s", bad, out)
				}
			}
			if tc.dry {
				if again, _, _, _, _ := runFixture(t, f, true); again != out {
					t.Errorf("a second dry run printed another plan:\n%s", again)
				}
				if strings.Contains(out, "opened") || strings.Contains(out, "merged") || strings.Contains(out, "created") {
					t.Errorf("dry run output claims a write:\n%s", out)
				}
			}
			ws := api.writes()
			var got []call
			for _, c := range ws {
				got = append(got, w(c.method, c.uri))
			}
			if !slices.Equal(got, tc.writes) {
				t.Errorf("writes %v, want %v", got, tc.writes)
			}
			if !maps.Equal(before, after) {
				t.Error("the pins directory changed")
			}
			if tc.check != nil && len(ws) > 0 {
				tc.check(t, ws)
			}
		})
	}
}

// baseFixture is trusted kit at 2.0.0 and guest tool at 1.2.0, each with a newer release upstream.
func baseFixture() fixture {
	f := fixture{pins: []pins.Pin{pin("kit", pins.Trusted, "2.0.0"), pin("tool", pins.Guest, "1.2.0")},
		extra: map[string]string{}, upstream: map[string]string{"/osv": `{"vulns":[]}`},
		routes: map[string]reply{listPRs: {body: "[]"}, "GET /repos/o/r/git/ref/heads/main": {body: `{"object":{"sha":"` + head + `"}}`},
			"GET /repos/o/r/issues?state=open&per_page=100": {body: "[]"}}}
	release(&f, "kit", "2.1.0", now.Add(-19*24*time.Hour), false)
	release(&f, "tool", "1.3.0", now.Add(-120*time.Hour), false)
	return f
}

// TestNewest: the freshness report, the guest rows rewritten at the newest stable release, the P7 line and the verification exit.
func TestNewest(t *testing.T) {
	tool := func(f *fixture) { f.pins = f.pins[1:] }
	stale := "tool guest 1.2.0 1.3.0 1.3.0 72h0m0s eligible"
	missed, failed := "P7 missed: tool", "bump: stopped: verification failed: tool"
	cases := []struct {
		name string
		edit func(*fixture)
		code int
		out  []string          // lines the output holds
		rows map[string]string // every file left in the pins directory, and its version
	}{
		{"pinned is the newest", func(f *fixture) { tool(f); f.pins[0].Version = "1.3.0" }, 0, []string{"tool guest 1.3.0 none none 0s backwards"}, map[string]string{"tool.json": "1.3.0"}},
		{"past cool-off plus slack: lag and P7 line printed, exit 0, row rewritten", tool, 0, []string{stale, missed}, map[string]string{"tool.json": "1.3.0"}},
		{"two eligible releases: lag counts from the oldest, unrounded", func(f *fixture) { // P7 missed by 29 minutes
			tool(f)
			f.args = append(f.args, "-dry-run")
			f.pins[0].Source, f.pins[0].Assets = pins.GitHubReleases, map[string]string{"amd64": "tool"}
			rel := `{"tag_name":%q,"created_at":%[2]q,"published_at":%[2]q,"assets":[{"name":"tool","browser_download_url":"{up}/dl","digest":"sha256:%x"}]}`
			sum := sha256.Sum256([]byte("artifact"))
			f.upstream["/tool"] = "[" + fmt.Sprintf(rel, "1.4.0", now.Add(-49*time.Hour).Format(time.RFC3339), sum) + "," +
				fmt.Sprintf(rel, "1.3.0", now.Add(-72*time.Hour-29*time.Minute).Format(time.RFC3339), sum) + "]"
			f.upstream["/dl"] = "artifact"
		}, 0, []string{"tool guest 1.2.0 1.4.0 1.4.0 24h0m0s eligible", missed}, map[string]string{"tool.json": "1.2.0"}},
		{"dry run writes nothing", func(f *fixture) { tool(f); f.args = append(f.args, "-dry-run") }, 0, []string{stale, missed}, map[string]string{"tool.json": "1.2.0"}},
		{"still cooling off: rewritten", func(f *fixture) { tool(f); release(f, "tool", "1.3.0", now.Add(-6*time.Hour), false) }, 0,
			[]string{"tool guest 1.2.0 none 1.3.0 0s cool-off"}, map[string]string{"tool.json": "1.3.0"}},
		{"trusted is reported, never written", func(f *fixture) { f.pins = f.pins[:1]; release(f, "kit", "2.1.0", now.Add(-8*24*time.Hour), false) }, 0,
			[]string{"kit trusted 2.0.0 2.1.0 2.1.0 24h0m0s eligible"}, map[string]string{"kit.json": "2.0.0"}},
		{"source error is reported", func(f *fixture) { tool(f); delete(f.upstream, "/tool/latest") }, 0, []string{"tool guest 1.2.0 none none 0s source-error"}, map[string]string{"tool.json": "1.2.0"}},
		{"verification fails: exit 1, nothing written", func(f *fixture) { tool(f); release(f, "tool", "1.3.0", now.Add(-120*time.Hour), true) }, 1,
			[]string{"tool guest 1.2.0 1.3.0 1.3.0 0s verify-failed", failed}, map[string]string{"tool.json": "1.2.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture()
			f.args = []string{"-newest"}
			tc.edit(&f)
			out, code, _, before, after := runFixture(t, f, false)
			if lines := strings.Split(out, "\n"); code != tc.code || slices.ContainsFunc(tc.out, func(l string) bool { return !slices.Contains(lines, l) }) {
				t.Errorf("exit %d, want %d; output lacks %q:\n%s", code, tc.code, tc.out, out)
			}
			got := map[string]string{}
			for name, text := range after {
				var p pins.Pin
				if err := json.Unmarshal([]byte(text), &p); err != nil {
					t.Fatal(err)
				}
				got[name] = p.Version
				sum := sha256.Sum256([]byte("artifact of tool 1.3.0"))
				if text != before[name] && (!p.Released.Equal(now) || p.Previous.Version != "1.2.0" || p.Artifacts["amd64"].SHA256 != hex.EncodeToString(sum[:]) ||
					!strings.HasSuffix(p.Artifacts["amd64"].URL, "/tool/1.3.0/linux-x64/tool")) {
					t.Errorf("rewritten row %s", text)
				}
			}
			if !maps.Equal(got, tc.rows) {
				t.Errorf("rows %v, want %v", got, tc.rows)
			}
		})
	}
}

// securityNote checks whether the body of the pull request, the third write, holds the security note.
func securityNote(want bool) func(*testing.T, []call) {
	return func(t *testing.T, cs []call) {
		var pr map[string]string
		if err := json.Unmarshal([]byte(cs[2].body), &pr); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(pr["body"], "security"); got != want {
			t.Errorf("security note %v, want %v: %q", got, want, pr["body"])
		}
	}
}

// checkOpened checks the branch, the row and the pull request of the guest class.
func checkOpened(t *testing.T, cs []call) {
	var ref, put, pr map[string]string
	for i, v := range []*map[string]string{&ref, &put, &pr} {
		if err := json.Unmarshal([]byte(cs[i].body), v); err != nil {
			t.Fatal(err)
		}
	}
	if ref["ref"] != "refs/heads/bump/guest-20261120" || ref["sha"] != head || put["branch"] != "bump/guest-20261120" || pr["head"] != "bump/guest-20261120" {
		t.Errorf("branch: %v %v %v", ref, put, pr)
	}
	raw, _ := base64.StdEncoding.DecodeString(put["content"])
	var row pins.Pin
	if err := json.Unmarshal(raw, &row); err != nil || !bytes.Equal(bump.Row(row), raw) {
		t.Fatalf("row does not round-trip: %v", err)
	}
	sum := sha256.Sum256([]byte("artifact of tool 1.3.0"))
	if row.Version != "1.3.0" || row.Previous == nil || row.Previous.Version != "1.2.0" || row.Artifacts["amd64"].SHA256 != hex.EncodeToString(sum[:]) ||
		!row.Released.Equal(now) {
		t.Errorf("row %+v", row)
	}
	if put["message"] != "bump: tool 1.2.0 to 1.3.0" || pr["title"] != "bump: guest pins" || pr["base"] != "main" ||
		pr["body"] != "- tool: 1.2.0 to 1.3.0, age 120h\n  - amd64 sha256 "+hex.EncodeToString(sum[:])+"\n" {
		t.Errorf("text: %q %v", put["message"], pr)
	}
}

// runFixture writes the pins directory, starts the recorded upstream and the stand-in, and runs the command; it returns the output and the directory's files
// before and after.
func runFixture(t *testing.T, f fixture, dry bool) (string, int, *standIn, map[string]string, map[string]string) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := f.upstream[r.URL.Path]
		switch {
		case !ok:
			http.NotFound(w, r)
		case body == drip:
			for range 200 {
				io.WriteString(w, "x")
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
		default:
			io.WriteString(w, strings.ReplaceAll(body, "{up}", "https://"+r.Host))
		}
	}))
	t.Cleanup(up.Close)
	api := &standIn{routes: f.routes}
	gh := httptest.NewServer(api)
	t.Cleanup(gh.Close)

	dir := t.TempDir()
	for _, p := range f.pins {
		p.Locator = up.URL + "/" + p.Name
		f.extra[p.Name+".json"] = string(bump.Row(p))
	}
	for name, body := range f.extra {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshot(t, dir)
	tool := bump.Tool{Pins: dir, Upstream: up.Client(), OSV: up.URL + "/osv", PinTime: 2 * time.Second, Now: now}
	tool.GitHub.Client = &http.Client{Timeout: 300 * time.Millisecond}
	var out, stderr bytes.Buffer
	tool.Out = &out
	args := append([]string{"-api", gh.URL, "-repo", "o/r"}, f.args...)
	if dry {
		args = append(args, "-dry-run")
	}
	env := map[string]string{"GITHUB_TOKEN": token}
	code := run(context.Background(), args, func(k string) string { return env[k] }, tool, &stderr)
	if strings.Contains(stderr.String(), token) {
		t.Error("stderr holds the token")
	}
	return out.String() + stderr.String(), code, api, before, snapshot(t, dir)
}

func snapshot(t *testing.T, dir string) map[string]string {
	m := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		m[e.Name()] = string(b)
	}
	return m
}
