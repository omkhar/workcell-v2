// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package pins

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// route is one recorded response. A body wins over a file.
type route struct {
	status  int // zero means 200
	file    string
	body    string
	header  map[string]string
	chunked bool // no Content-Length, so the cap is met while reading

	// A registry's anonymous pull: token, when set, is the bearer the route wants.
	// Without it the route answers 401 and the challenge, which by default names
	// this server's /token route. A query, when set, is the one the route accepts.
	token     string
	challenge string
	query     string
}

func serve(t *testing.T, routes map[string]route) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt, ok := routes[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if rt.query != "" && r.URL.RawQuery != rt.query {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		if rt.token != "" && r.Header.Get("Authorization") != "Bearer "+rt.token {
			challenge := cmp.Or(rt.challenge, `Bearer realm="https://`+r.Host+`/token",service="registry.example",scope="repository:vendor/tool:pull"`)
			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body := []byte(rt.body)
		if rt.file != "" {
			var err error
			if body, err = os.ReadFile(filepath.Join("testdata", rt.file)); err != nil {
				t.Error(err)
			}
		}
		for k, v := range rt.header {
			w.Header().Set(k, v)
		}
		if !rt.chunked {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(max(rt.status, 200))
		w.Write(body)
		if f, ok := w.(http.Flusher); ok && rt.chunked {
			f.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ts(s ...string) []time.Time {
	var out []time.Time
	for _, v := range s {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			panic(err)
		}
		out = append(out, t)
	}
	return out
}

func both(a Artifact) map[string]Artifact { return map[string]Artifact{"amd64": a, "arm64": a} }

func fileDigest(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestCandidates(t *testing.T) {
	const reg = "https://registry.example/@vendor/tool/-/tool-"
	const gh = "https://github.example/vendor/tool/releases/download/"
	npmPin := Pin{Name: "tool", Source: NPM, Locator: "/@vendor%2ftool"}
	ghPin := Pin{Name: "tool", Source: GitHubReleases, Locator: "/repos/vendor/tool/releases",
		Assets: map[string]string{"amd64": "tool-linux-amd64.tar.gz", "arm64": "tool-linux-arm64.tar.gz"}}
	vendorPin := Pin{Name: "claude", Source: VendorManifest, Locator: "/root", Assets: map[string]string{"amd64": "linux-x64", "arm64": "linux-arm64"}}
	ociPin := Pin{Name: "tool", Source: OCI, Locator: "/v2/vendor/tool"}

	npmOK := map[string]route{"/@vendor%2ftool": {file: "npm-tool.json"}}
	ghOK := map[string]route{"/repos/vendor/tool/releases": {file: "github-releases.json"}}
	vendorOK := map[string]route{"/root/latest": {file: "vendor-latest.txt"}, "/root/1.2.0/manifest.json": {file: "vendor-manifest.json"}}
	ociOK := map[string]route{
		"/token":                          {body: `{"token": "tok"}`, query: "scope=repository%3Avendor%2Ftool%3Apull&service=registry.example"},
		"/v2/vendor/tool/tags/list":       {file: "oci-tags.json", token: "tok"},
		"/v2/vendor/tool/manifests/1.2.0": {file: "oci-manifest-1.2.0.json", token: "tok"},
		"/v2/vendor/tool/manifests/1.1.0": {file: "oci-manifest-1.1.0.json", token: "tok"},
	}

	ociWant := func(base string) []Candidate {
		d2, d1 := fileDigest(t, "oci-manifest-1.2.0.json"), fileDigest(t, "oci-manifest-1.1.0.json")
		return []Candidate{
			{Release: Release{Version: "1.2.0", Artifacts: both(Artifact{URL: base + "/v2/vendor/tool/manifests/sha256:" + d2, SHA256: d2})}, Timestamps: ts("2026-10-20T09:30:00Z")},
			{Release: Release{Version: "1.1.0", Artifacts: both(Artifact{URL: base + "/v2/vendor/tool/manifests/sha256:" + d1, SHA256: d1})}},
		}
	}
	type row struct {
		name   string
		pin    Pin
		routes map[string]route
		want   func(base string) []Candidate // nil means an error is expected
	}
	// withRoute is routes with one route replaced.
	withRoute := func(routes map[string]route, path string, rt route) map[string]route {
		m := maps.Clone(routes)
		m[path] = rt
		return m
	}
	// failures adds the rows every source shares: the upstream answers one of its
	// requests with an error status, a truncated body, or a redirect off https or
	// in a loop.
	failures := func(pin Pin, routes map[string]route, paths ...string) []row {
		var rows []row
		for _, p := range paths {
			for name, rt := range map[string]route{
				"HTTP 500":         {status: 500, body: "oops"},
				"truncated JSON":   {body: `{"versions": {"1.2.0": {"dist"`},
				"redirect to http": {status: 302, header: map[string]string{"Location": "http://example.invalid/x"}},
				"redirect loop":    {status: 302, header: map[string]string{"Location": p}},
			} {
				rows = append(rows, row{name: string(pin.Source) + " " + p + " " + name, pin: pin, routes: withRoute(routes, p, rt)})
			}
		}
		return rows
	}

	// getter.get is shared by every source, so one body of cap+1 bytes per
	// transport form covers them all.
	over := string(make([]byte, maxBytes+1))

	tests := []row{
		{name: "over the cap with Content-Length", pin: npmPin, routes: withRoute(npmOK, "/@vendor%2ftool", route{body: over})},
		{name: "over the cap chunked", pin: npmPin, routes: withRoute(npmOK, "/@vendor%2ftool", route{body: over, chunked: true})},
		{name: "npm", pin: npmPin, routes: npmOK, want: func(string) []Candidate {
			return []Candidate{
				{Release: Release{Version: "0.0.45-gabc1234", Artifacts: both(Artifact{URL: reg + "0.0.45-gabc1234.tgz"})}, PreRelease: true, Timestamps: ts("2026-09-01T08:00:00Z")},
				{Release: Release{Version: "1.1.0", Artifacts: both(Artifact{URL: reg + "1.1.0.tgz"})}, Deprecated: true, Timestamps: []time.Time{ts("2026-09-10T10:00:00Z")[0].Add(123 * time.Millisecond)}},
				{Release: Release{Version: "1.2.0", Artifacts: both(Artifact{URL: reg + "1.2.0.tgz"})}, Timestamps: ts("2026-10-20T09:30:00Z")},
				{Release: Release{Version: "1.3.0-rc.1", Artifacts: both(Artifact{URL: reg + "1.3.0-rc.1.tgz"})}, PreRelease: true, Timestamps: ts("2026-10-25T09:30:00Z")},
			}
		}},
		{name: "npm no version", pin: npmPin, routes: withRoute(npmOK, "/@vendor%2ftool", route{body: `{"versions": {}}`}), want: func(string) []Candidate { return []Candidate{} }},
		{name: "npm error document", pin: npmPin, routes: withRoute(npmOK, "/@vendor%2ftool", route{body: `{"error": "Not found"}`})},
		{name: "npm missing time", pin: npmPin, routes: withRoute(npmOK, "/@vendor%2ftool", route{
			body: `{"versions": {"1.2.0": {"dist": {"tarball": "https://r.example/t.tgz"}}}, "time": {}}`})},
		{name: "npm bad time", pin: npmPin, routes: withRoute(npmOK, "/@vendor%2ftool", route{
			body: `{"versions": {"1.2.0": {"dist": {"tarball": "https://r.example/t.tgz"}}}, "time": {"1.2.0": "yesterday"}}`})},
		{name: "npm http tarball", pin: npmPin, routes: withRoute(npmOK, "/@vendor%2ftool", route{
			body: `{"versions": {"1.2.0": {"dist": {"tarball": "http://r.example/t.tgz"}}}, "time": {"1.2.0": "2026-10-20T09:30:00Z"}}`})},

		{name: "github", pin: ghPin, routes: ghOK, want: func(string) []Candidate {
			return []Candidate{
				{Release: Release{Version: "v1.4.0", Artifacts: map[string]Artifact{}}, PreRelease: true, Timestamps: ts("2026-10-30T10:00:00Z")},
				{Release: Release{Version: "v1.3.0-rc.1", Artifacts: map[string]Artifact{}}, PreRelease: true, Timestamps: ts("2026-10-25T10:00:00Z", "2026-10-25T11:00:00Z")},
				{Release: Release{Version: "v1.2.0", Artifacts: map[string]Artifact{
					"amd64": {URL: gh + "v1.2.0/tool-linux-amd64.tar.gz", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
					"arm64": {URL: gh + "v1.2.0/tool-linux-arm64.tar.gz"}}}, Timestamps: ts("2026-10-20T09:00:00Z", "2026-10-20T09:30:00Z")},
				{Release: Release{Version: "v1.1.0", Artifacts: map[string]Artifact{
					"amd64": {URL: gh + "v1.1.0/tool-linux-amd64.tar.gz", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
					"arm64": {URL: gh + "v1.1.0/tool-linux-arm64.tar.gz", SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}, Timestamps: ts("2026-09-10T09:00:00Z", "2026-09-10T09:15:00Z")},
			}
		}},
		{name: "github no release", pin: ghPin, routes: withRoute(ghOK, "/repos/vendor/tool/releases", route{body: `[]`}), want: func(string) []Candidate { return []Candidate{} }},
		{name: "github error document", pin: ghPin, routes: withRoute(ghOK, "/repos/vendor/tool/releases", route{body: `{"message": "API rate limit exceeded"}`})},
		{name: "github stable release lacks an asset", pin: ghPin, routes: withRoute(ghOK, "/repos/vendor/tool/releases", route{
			body: `[{"tag_name": "v1.2.0", "created_at": "2026-10-20T09:00:00Z", "assets": []}]`})},
		{name: "github bad digest", pin: ghPin, routes: withRoute(ghOK, "/repos/vendor/tool/releases", route{
			body: `[{"tag_name": "v1.2.0", "created_at": "2026-10-20T09:00:00Z", "assets": [
				{"name": "tool-linux-amd64.tar.gz", "browser_download_url": "https://g.example/a", "digest": "sha512:ab"},
				{"name": "tool-linux-arm64.tar.gz", "browser_download_url": "https://g.example/b"}]}]`})},
		{name: "github no timestamp", pin: ghPin, routes: withRoute(ghOK, "/repos/vendor/tool/releases", route{
			body: `[{"tag_name": "v1.4.0", "draft": true, "assets": []}]`})},
		{name: "github asset no release carries", pin: Pin{Name: "tool", Source: GitHubReleases, Locator: ghPin.Locator,
			Assets: map[string]string{"amd64": "nope.tar.gz"}}, routes: ghOK},
		{name: "github no asset row", pin: Pin{Name: "tool", Source: GitHubReleases, Locator: ghPin.Locator}, routes: ghOK},

		{name: "vendor", pin: vendorPin, routes: vendorOK, want: func(base string) []Candidate {
			return []Candidate{{Release: Release{Version: "1.2.0", Artifacts: map[string]Artifact{
				"amd64": {URL: base + "/root/1.2.0/linux-x64/claude", SHA256: "3333333333333333333333333333333333333333333333333333333333333333"},
				"arm64": {URL: base + "/root/1.2.0/linux-arm64/claude", SHA256: "2222222222222222222222222222222222222222222222222222222222222222"}}},
				Timestamps: ts("2026-10-20T08:00:00Z")}}
		}},
		{name: "vendor latest is not a version", pin: vendorPin, routes: withRoute(vendorOK, "/root/latest", route{body: "../../x\n"})},
		{name: "vendor manifest missing", pin: vendorPin, routes: withRoute(vendorOK, "/root/latest", route{body: "1.1.0\n"})},
		{name: "vendor manifest reports another version", pin: vendorPin, routes: withRoute(vendorOK, "/root/1.2.0/manifest.json", route{
			body: `{"version": "1.1.9", "buildDate": "2026-10-20T08:00:00Z", "platforms": {}}`})},
		{name: "vendor missing platform", pin: vendorPin, routes: withRoute(vendorOK, "/root/1.2.0/manifest.json", route{
			body: `{"version": "1.2.0", "buildDate": "2026-10-20T08:00:00Z", "platforms": {"linux-x64": {"checksum": "3333333333333333333333333333333333333333333333333333333333333333"}}}`})},
		{name: "vendor bad checksum", pin: vendorPin, routes: withRoute(vendorOK, "/root/1.2.0/manifest.json", route{
			body: `{"version": "1.2.0", "buildDate": "2026-10-20T08:00:00Z", "platforms": {"linux-x64": {"checksum": "XYZ"}, "linux-arm64": {"checksum": "XYZ"}}}`})},
		{name: "vendor missing build date", pin: vendorPin, routes: withRoute(vendorOK, "/root/1.2.0/manifest.json", route{
			body: `{"version": "1.2.0", "platforms": {}}`})},

		{name: "oci", pin: ociPin, routes: ociOK, want: ociWant},
		{name: "oci token as access_token", pin: ociPin, routes: withRoute(ociOK, "/token", route{body: `{"access_token": "tok"}`}), want: ociWant},
		{name: "oci token endpoint gives no token", pin: ociPin, routes: withRoute(ociOK, "/token", route{body: `{}`})},
		{name: "oci token endpoint fails", pin: ociPin, routes: withRoute(ociOK, "/token", route{status: 500, body: "oops"})},
		{name: "oci token is refused", pin: ociPin, routes: withRoute(ociOK, "/token", route{body: `{"token": "other"}`})},
		{name: "oci challenge realm is http", pin: ociPin, routes: withRoute(ociOK, "/v2/vendor/tool/tags/list", route{file: "oci-tags.json", token: "tok",
			challenge: `Bearer realm="http://auth.example/token",service="registry.example",scope="repository:vendor/tool:pull"`})},
		{name: "oci challenge is not Bearer", pin: ociPin, routes: withRoute(ociOK, "/v2/vendor/tool/tags/list", route{file: "oci-tags.json", token: "tok",
			challenge: `Basic realm="registry"`})},
		{name: "oci header matches", pin: ociPin, routes: withRoute(ociOK, "/v2/vendor/tool/manifests/1.2.0", route{file: "oci-manifest-1.2.0.json",
			header: map[string]string{"Docker-Content-Digest": "sha256:" + fileDigest(t, "oci-manifest-1.2.0.json")}}), want: ociWant},
		{name: "oci header differs", pin: ociPin, routes: withRoute(ociOK, "/v2/vendor/tool/manifests/1.2.0", route{file: "oci-manifest-1.2.0.json",
			header: map[string]string{"Docker-Content-Digest": "sha256:" + fileDigest(t, "oci-manifest-1.1.0.json")}})},
		{name: "oci paginated tag list", pin: ociPin, routes: withRoute(ociOK, "/v2/vendor/tool/tags/list", route{file: "oci-tags.json",
			header: map[string]string{"Link": `</v2/vendor/tool/tags/list?last=1.2.0>; rel="next"`}})},
		{name: "oci no tags", pin: ociPin, routes: withRoute(ociOK, "/v2/vendor/tool/tags/list", route{body: `{"name": "vendor/tool", "tags": null}`}), want: func(string) []Candidate { return []Candidate{} }},
		{name: "oci error document", pin: ociPin, routes: withRoute(ociOK, "/v2/vendor/tool/tags/list", route{body: `{"errors": [{"code": "DENIED"}]}`})},
		{name: "oci bad created", pin: ociPin, routes: withRoute(ociOK, "/v2/vendor/tool/manifests/1.2.0", route{
			body: `{"annotations": {"org.opencontainers.image.created": "last week"}}`})},
	}
	tests = append(tests, failures(npmPin, npmOK, "/@vendor%2ftool")...)
	tests = append(tests, failures(ghPin, ghOK, "/repos/vendor/tool/releases")...)
	tests = append(tests, failures(vendorPin, vendorOK, "/root/latest", "/root/1.2.0/manifest.json")...)
	tests = append(tests, failures(ociPin, ociOK, "/v2/vendor/tool/tags/list", "/v2/vendor/tool/manifests/1.2.0")...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := serve(t, tt.routes)
			pin := tt.pin
			pin.Locator = srv.URL + pin.Locator
			got, err := Candidates(context.Background(), srv.Client(), pin)
			if tt.want == nil {
				if err == nil || got != nil {
					t.Fatalf("got %v, %v; want an error and no candidate", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := tt.want(srv.URL); !reflect.DeepEqual(got, want) {
				t.Errorf("got  %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestCandidatesRefusals(t *testing.T) {
	tests := []struct {
		name string
		pin  Pin
	}{
		{"unknown source", Pin{Name: "x", Source: "ftp", Locator: "https://example.com/"}},
		{"plain http locator", Pin{Name: "x", Source: NPM, Locator: "http://example.com/x"}},
		{"no locator", Pin{Name: "x", Source: NPM}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Candidates(context.Background(), &http.Client{}, tt.pin)
			if err == nil || got != nil {
				t.Fatalf("got %v, %v; want an error and no candidate", got, err)
			}
		})
	}
}
