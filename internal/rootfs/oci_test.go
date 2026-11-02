// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	tarGz  = "application/vnd.oci.image.layer.v1.tar+gzip"
	ociMan = "application/vnd.oci.image.manifest.v1+json"
	ociIdx = "application/vnd.oci.image.index.v1+json"
)

type mem struct {
	name, link, body string
	typ              byte
	major, minor     int64
}

func tarOf(ms ...mem) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, m := range ms {
		h := &tar.Header{Name: m.name, Linkname: m.link, Typeflag: m.typ, Mode: 0o644, Devmajor: m.major, Devminor: m.minor}
		if m.typ == tar.TypeReg {
			h.Size = int64(len(m.body))
		}
		if err := w.WriteHeader(h); err != nil {
			panic(err)
		}
		_, _ = w.Write([]byte(m.body))
	}
	_ = w.Close()
	return b.Bytes()
}

func gz(b []byte) []byte {
	var o bytes.Buffer
	w := gzip.NewWriter(&o)
	_, _ = w.Write(b)
	_ = w.Close()
	return o.Bytes()
}

func dg(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }

func reg(name, body string) mem { return mem{name: name, body: body, typ: tar.TypeReg} }
func dir(name string) mem       { return mem{name: name, typ: tar.TypeDir} }
func hard(name, to string) mem  { return mem{name: name, link: to, typ: tar.TypeLink} }
func sym(name, to string) mem   { return mem{name: name, link: to, typ: tar.TypeSymlink} }

type fixture struct {
	t      *testing.T
	routes map[string][]byte // host+path to body
	redir  map[string]string // host+path to a Location
	seen   map[string][]string
	mu     sync.Mutex
	client *http.Client
	img    Image
	blobs  []string
}

// newFixture serves layers (tar.gz blobs) behind an index, a manifest, a 401
// challenge and an anonymous token endpoint, all on https.
func newFixture(t *testing.T, layers ...[]byte) *fixture {
	f := &fixture{t: t, routes: map[string][]byte{}, redir: map[string]string{}, seen: map[string][]string{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		key := r.Host + r.URL.Path
		f.seen[r.Host] = append(f.seen[r.Host], r.Header.Get("Authorization"))
		switch {
		case r.Host == "auth.test":
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case r.Host == "registry.test" && r.Header.Get("Authorization") != "Bearer tok":
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.test/token",service="reg",scope="repository:lib/x:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		case f.redir[key] != "":
			http.Redirect(w, r, f.redir[key], http.StatusTemporaryRedirect)
		case f.routes[key] != nil:
			_, _ = w.Write(f.routes[key])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	f.client = srv.Client()
	tr := f.client.Transport.(*http.Transport)
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	tr.TLSClientConfig.ServerName = "example.com"
	var descs []map[string]any
	for _, l := range layers {
		blob := gz(l)
		d := dg(blob)
		f.routes["registry.test/v2/lib/x/blobs/"+d] = blob
		f.blobs = append(f.blobs, d)
		descs = append(descs, map[string]any{"mediaType": tarGz, "digest": d, "size": len(blob)})
	}
	f.publish(descs)
	return f
}

// publish (re)writes the manifest with the given layer descriptors and an index over it.
func (f *fixture) publish(layers []map[string]any) {
	f.manifest(map[string]any{"mediaType": ociMan, "layers": layers})
}

func (f *fixture) manifest(doc map[string]any) {
	mb, _ := json.Marshal(doc)
	md := dg(mb)
	f.routes["registry.test/v2/lib/x/manifests/"+md] = mb
	plat := func(arch string) map[string]any { return map[string]any{"os": "linux", "architecture": arch} }
	ib, _ := json.Marshal(map[string]any{"mediaType": ociIdx, "manifests": []map[string]any{
		{"mediaType": ociMan, "digest": dg([]byte("decoy")), "platform": plat("riscv64")},
		{"mediaType": ociMan, "digest": md, "platform": plat("arm64")},
	}})
	id := dg(ib)
	f.routes["registry.test/v2/lib/x/manifests/"+id] = ib
	f.img = Image{Registry: "https://registry.test", Repository: "lib/x", Digest: id, OS: "linux", Arch: "arm64"}
}

func (f *fixture) pull(tree *Tree) (string, error) {
	return Pull(context.Background(), f.client, f.img, tree)
}

// dump lists every entry of the tree as "path kind", sorted, and fails on a bad name.
func dump(t *testing.T, tr *Tree) []string {
	var out []string
	var walk func(p string, n *Node)
	walk = func(p string, n *Node) {
		for name, k := range n.kids {
			if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
				t.Errorf("entry %q under %q escapes", name, p)
			}
			out = append(out, fmt.Sprintf("%s/%s %d", p, name, k.Kind))
			walk(p+"/"+name, k)
		}
	}
	walk("", tr.root)
	slices.Sort(out)
	return out
}

func TestPullLayers(t *testing.T) {
	base := tarOf(
		dir("./"), dir("etc/"), reg("etc/hello", "v1"), reg("etc/gone", "x"),
		dir("opt/"), reg("opt/a", "a"), reg("opt/b", "b"),
		reg("bin/sh", "shell"), hard("bin/ls", "bin/sh"), sym("lnk", "../../x"),
		mem{name: "dev/null", typ: tar.TypeChar, major: 1, minor: 3},
		mem{name: "dev/sda", typ: tar.TypeBlock, major: 8, minor: 0},
		mem{name: "dev/fifo", typ: tar.TypeFifo},
	)
	top := tarOf(
		reg("etc/hello", "v2"), reg("etc/.wh.gone", ""), reg("opt/.wh..wh..opq", ""), reg("opt/c", "c"),
		reg("new/deep/file", "d"), reg("a/.wh.absent", ""),
	)
	f := newFixture(t, base, top)
	tree := NewTree()
	got, err := f.pull(tree)
	if err != nil {
		t.Fatal(err)
	}
	if want := f.img.Digest; got == want || !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("returned digest %q should be the manifest's, not the index %q", got, want)
	}
	for _, c := range []struct {
		path string
		kind Kind
		data string
	}{
		{"/etc/hello", File, "v2"}, {"/opt/c", File, "c"}, {"/new/deep/file", File, "d"},
		{"/bin/ls", File, "shell"}, {"/lnk", Symlink, ""}, {"/dev/null", CharDev, ""},
		{"/dev/sda", BlockDev, ""}, {"/dev/fifo", FIFO, ""}, {"/new/deep", Dir, ""},
	} {
		n := tree.Lookup(c.path)
		if n == nil || n.Kind != c.kind || string(n.Data) != c.data {
			t.Errorf("%s: %+v", c.path, n)
		}
	}
	for _, gone := range []string{"/etc/gone", "/opt/a", "/opt/b", "/a"} {
		if tree.Lookup(gone) != nil {
			t.Errorf("%s survived", gone)
		}
	}
	if tree.Lookup("/opt") == nil || tree.Lookup("/bin/ls") != tree.Lookup("/bin/sh") {
		t.Error("opaque dir itself was lost, or the hard link does not share a node")
	}
	if n := tree.Lookup("/lnk"); n.Target != "../../x" {
		t.Errorf("symlink target %q", n.Target)
	}
	if n := tree.Lookup("/dev/null"); n.Major != 1 || n.Minor != 3 {
		t.Errorf("device %d:%d", n.Major, n.Minor)
	}
}

func TestPullRefusals(t *testing.T) {
	good := tarOf(reg("f", "x"))
	for _, c := range []struct {
		name string
		set  func(f *fixture)
		want string
	}{
		{"manifest bytes differ from the requested digest", func(f *fixture) {
			f.routes["registry.test/v2/lib/x/manifests/"+f.img.Digest] = []byte(`{"mediaType":"` + ociIdx + `","manifests":[]}`)
		}, "does not match its digest"},
		{"layer bytes differ from the descriptor", func(f *fixture) {
			f.routes["registry.test/v2/lib/x/blobs/"+f.blobs[0]] = gz(tarOf(reg("f", "evil")))
		}, "does not match its digest"},
		{"layer longer than its descriptor", func(f *fixture) {
			f.routes["registry.test/v2/lib/x/blobs/"+f.blobs[0]] = append(gz(good), 0)
		}, "layer 0"},
		{"descriptor over the blob cap", func(f *fixture) {
			f.publish([]map[string]any{{"mediaType": tarGz, "digest": f.blobs[0], "size": maxBlob + 1}})
		}, "outside the cap"},
		{"zstd layer", func(f *fixture) {
			f.publish([]map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": f.blobs[0], "size": 10}})
		}, "unsupported layer media type"},
		{"digest with a path in it", func(f *fixture) {
			f.publish([]map[string]any{{"mediaType": tarGz, "digest": "sha256:../" + strings.Repeat("a", 60), "size": 10}})
		}, "not a sha256 digest"},
		{"no manifest for the platform", func(f *fixture) { f.img.Arch = "s390x" }, "no manifest for linux/s390x"},
		{"not a manifest", func(f *fixture) { f.manifest(map[string]any{"mediaType": "text/html"}) }, "not an OCI or Docker"},
		{"http registry", func(f *fixture) { f.img.Registry = "http://registry.test" }, "bare https"},
		{"registry with a path", func(f *fixture) { f.img.Registry = "https://registry.test/v2" }, "bare https"},
		{"bad repository", func(f *fixture) { f.img.Repository = "lib/../x" }, "bad repository"},
		{"missing blob", func(f *fixture) { delete(f.routes, "registry.test/v2/lib/x/blobs/"+f.blobs[0]) }, "HTTP 404"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, good)
			c.set(f)
			if _, err := f.pull(NewTree()); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestPullNoBearerChallenge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	t.Cleanup(srv.Close)
	img := Image{Registry: srv.URL, Repository: "lib/x", Digest: dg(nil), OS: "linux", Arch: "arm64"}
	if _, err := Pull(context.Background(), srv.Client(), img, NewTree()); err == nil || !strings.Contains(err.Error(), "Bearer challenge") {
		t.Fatalf("got %v", err)
	}
}

func TestPullTokenStaysWithRegistry(t *testing.T) {
	f := newFixture(t, tarOf(reg("f", "x")))
	f.redir["registry.test/v2/lib/x/blobs/"+f.blobs[0]] = "https://cdn.test/blob"
	f.routes["cdn.test/blob"] = f.routes["registry.test/v2/lib/x/blobs/"+f.blobs[0]]
	if _, err := f.pull(NewTree()); err != nil {
		t.Fatal(err)
	}
	if got := f.seen["cdn.test"]; len(got) != 1 || got[0] != "" {
		t.Errorf("the CDN saw Authorization %q", got)
	}
	if !slices.Contains(f.seen["registry.test"], "Bearer tok") || slices.Contains(f.seen["auth.test"], "Bearer tok") {
		t.Errorf("token went to the wrong place: %v", f.seen)
	}
	f.redir["registry.test/v2/lib/x/blobs/"+f.blobs[0]] = "http://cdn.test/blob"
	if _, err := f.pull(NewTree()); err == nil {
		t.Error("a redirect to http was followed")
	}
}

func TestApplyLayerRefusals(t *testing.T) {
	for _, c := range []struct {
		name  string
		pre   []byte // applied first, and must succeed
		layer []byte
		limit int64
		want  string
	}{
		{"absolute name", nil, tarOf(reg("/etc/passwd", "x")), 1 << 20, "absolute name"},
		{"absolute dir", nil, tarOf(dir("/etc/")), 1 << 20, "absolute name"},
		{"dotdot", nil, tarOf(reg("../evil", "x")), 1 << 20, "holds .."},
		{"dotdot inside", nil, tarOf(reg("a/../../evil", "x")), 1 << 20, "holds .."},
		{"dotdot symlink parent", nil, tarOf(reg("keep/../../evil", "x")), 1 << 20, "holds .."},
		{"empty name", nil, tarOf(reg("", "x")), 1 << 20, "empty name"},
		{"name over PATH_MAX", nil, tarOf(reg(strings.Repeat("a/", 3000)+"f", "x")), 1 << 20, "name too long"},
		{"double slash", nil, tarOf(reg("a//b", "x")), 1 << 20, "bad path"},
		{"hard link to an absolute name", nil, tarOf(hard("l", "/etc/passwd")), 1 << 20, "absolute name"},
		{"hard link with dotdot", nil, tarOf(hard("l", "../keep")), 1 << 20, "holds .."},
		{"hard link to nothing", nil, tarOf(hard("l", "nosuch")), 1 << 20, "no such path"},
		{"hard link to a dir", tarOf(dir("d/")), tarOf(hard("l", "d")), 1 << 20, "hard-link a directory"},
		{"write through a symlink", tarOf(sym("s", "/")), tarOf(reg("s/evil", "x")), 1 << 20, "not a directory"},
		{"whiteout of dot", nil, tarOf(reg(".wh...", "")), 1 << 20, "bad path"},
		{"unknown type", nil, tarOf(mem{name: "x", typ: tar.TypeCont}), 1 << 20, "unsupported tar type"},
		{"device out of range", nil, tarOf(mem{name: "x", typ: tar.TypeChar, major: 1 << 12}), 1 << 20, "out of range"},
		{"file over the cap", nil, tarOf(reg("big", strings.Repeat("a", 4096))), 2048, "over the size cap"},
		{"stream over the cap", nil, tarOf(reg("a", "1")), 512, "over the size cap"},
		{"truncated", nil, tarOf(reg("a", strings.Repeat("a", 600)))[:700], 1 << 20, "tar unreadable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tree := NewTree()
			_ = tree.Put("/keep", Node{Kind: File, Data: []byte("k")})
			if c.pre != nil {
				if _, err := applyLayer(tree, bytes.NewReader(c.pre), c.limit); err != nil {
					t.Fatal(err)
				}
			}
			before := dump(t, tree)
			_, err := applyLayer(tree, bytes.NewReader(c.layer), c.limit)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if after := dump(t, tree); !slices.Equal(before, after) {
				t.Errorf("the tree changed: %v", after)
			}
			for _, p := range []string{"/etc/passwd", "/evil", "/l"} {
				if tree.Lookup(p) != nil {
					t.Errorf("%s was written", p)
				}
			}
		})
	}
}

// A gzip bomb: a megabyte of gzip that holds far more than the cap.
func TestApplyLayerBomb(t *testing.T) {
	bomb := gz(tarOf(reg("zeros", strings.Repeat("\x00", 8<<20))))
	zr, err := gzip.NewReader(bytes.NewReader(bomb))
	if err != nil {
		t.Fatal(err)
	}
	tree := NewTree()
	if _, err := applyLayer(tree, zr, 1<<20); err == nil || !strings.Contains(err.Error(), "size cap") {
		t.Fatalf("got %v", err)
	}
	if tree.Lookup("/zeros") != nil {
		t.Error("the bomb was written")
	}
}

func FuzzLayer(f *testing.F) {
	f.Add(tarOf(dir("a/"), reg("a/b", "x"), hard("c", "a/b"), sym("s", "../x"), reg("a/.wh.b", ""), reg(".wh..wh..opq", "")))
	f.Add(tarOf(reg("../x", "y"), reg("/y", "z"), hard("h", "nosuch")))
	f.Fuzz(func(t *testing.T, data []byte) {
		tree := NewTree()
		_, _ = applyLayer(tree, bytes.NewReader(data), 1<<20)
		dump(t, tree)
	})
}
