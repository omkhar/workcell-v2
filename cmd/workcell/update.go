// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/internal/artifact"
	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/provider"
	"github.com/omkhar/workcell/v2/internal/rootfs"
	rows "github.com/omkhar/workcell/v2/pins"
)

// maxLayer bounds the bytes of tar stream, and of file data, that one provider CLI's
// artifact may unpack to. The tree lives in memory, so a gzip bomb ends here.
const maxLayer = 1 << 30

// update is `workcell update [--to VERSION | --rollback] [AGENT]`: the host side of a provider
// CLI's install (A10). The CLI's version is its row under pins/ and nowhere else. The artifact
// is fetched on the host by the row's URL, refused unless its sha256 is the row's (B8), and
// unpacked into a layer, an ext4 image under the data directory that a session attaches
// read-only. A `current` marker names the layer only once the image is complete; the layer
// it replaces stays as `previous`, which --rollback goes back to without fetching. --to takes
// the row's current or previous release. With no agent, every provider that has a row is done.
func update(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	to := fs.String("to", "", "")
	rollback := fs.Bool("rollback", false, "")
	if fs.Parse(args) != nil || fs.NArg() > 1 || (*to != "" && *rollback) || (fs.NArg() == 0 && (*to != "" || *rollback)) {
		fmt.Fprintln(stderr, "usage: workcell update [--to VERSION | --rollback] [AGENT]\n  installs the pinned release of a provider CLI, or of every provider;"+
			" --to takes the row's current or previous release, --rollback the layer kept from before")
		return 2
	}
	dir, err := dataDir()
	in := installer{dir: dir, client: http.DefaultClient}
	var provs []provider.Provider
	if err == nil {
		in.rows, err = rows.All()
	}
	if err == nil {
		provs, err = provider.All()
	}
	if err == nil && fs.NArg() == 1 {
		p, ok := provider.Lookup(fs.Arg(0))
		if !ok {
			err = fmt.Errorf("no provider named %q", fs.Arg(0))
		}
		provs = []provider.Provider{p}
	}
	if err != nil {
		fmt.Fprintln(stderr, "workcell update:", err)
		return 2
	}
	rc := 0
	for _, p := range provs {
		if _, err := in.row(p); err != nil && fs.NArg() == 0 {
			continue
		}
		line, err := in.update(context.Background(), p, *to, *rollback)
		if err != nil {
			fmt.Fprintln(stderr, "workcell update:", err)
			rc = 1
			continue
		}
		fmt.Fprintln(stdout, line)
	}
	return rc
}

// installer is what update works with: the data directory, the rows under pins/ and the
// client that fetches an artifact. A test passes its own rows and a loopback client (A11).
type installer struct {
	dir    string
	rows   []pins.Pin
	client *http.Client
}

// update brings the provider p to the row's current release, to the release to names, or
// back to the layer kept from before, and returns the result line: agent, version, digest prefix.
func (in installer) update(ctx context.Context, p provider.Provider, to string, rollback bool) (string, error) {
	row, err := in.row(p)
	if err != nil {
		return "", in.refuse(p.Name, "", "", err)
	}
	dir := filepath.Join(in.dir, "layers", p.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	cur, prev := marker(dir, "current"), marker(dir, "previous")
	if rollback {
		if cur == "" || prev == "" {
			return "", in.refuse(p.Name, "", "", errors.New("there is no earlier layer to roll back to"))
		}
		return in.point(p.Name, row, dir, prev, cur, "rolled_back")
	}
	rel := row.Release
	switch {
	case to == "" || to == row.Version:
	case row.Previous != nil && to == row.Previous.Version:
		rel = *row.Previous
	default:
		return "", in.refuse(p.Name, to, "", fmt.Errorf("version %s is not the row's current %s or its previous one", to, row.Version))
	}
	a, ok := rel.Artifacts[runtime.GOARCH]
	if !ok || len(a.SHA256) != 64 {
		return "", in.refuse(p.Name, rel.Version, "", fmt.Errorf("release %s has no artifact with a digest for %s", rel.Version, runtime.GOARCH))
	}
	name := imageName(rel.Version, a.SHA256)
	switch name {
	case cur:
		v, d := known(row, name)
		return p.Name + " " + v + " " + d[:min(16, len(d))], nil
	case prev:
		return in.point(p.Name, row, dir, prev, cur, "rolled_back")
	}
	if err := in.fetch(ctx, dir, name, p.Binary, a); err != nil {
		return "", in.refuse(p.Name, rel.Version, a.SHA256, err)
	}
	return in.point(p.Name, row, dir, name, cur, "installed")
}

// row is the pins/ row of p: the pin its install names, when it is installed as a binary.
func (in installer) row(p provider.Provider) (pins.Pin, error) {
	if p.Install.Method != "binary" {
		return pins.Pin{}, fmt.Errorf("provider %s is installed by %s; update installs binaries only", p.Name, p.Install.Method)
	}
	i := slices.IndexFunc(in.rows, func(r pins.Pin) bool { return r.Name == p.Install.Pin })
	if i < 0 {
		return pins.Pin{}, fmt.Errorf("provider %s names pin %s, which has no row under pins/", p.Name, p.Install.Pin)
	}
	if in.rows[i].Version == "" {
		return pins.Pin{}, fmt.Errorf("provider %s names pin %s, whose row pins no release yet", p.Name, p.Install.Pin)
	}
	return in.rows[i], nil
}

// fetch downloads the artifact a into dir as the image name, through its digest check (B8):
// the bytes go to a temporary file as they are hashed, and are unpacked only once the
// digest is the row's. A mismatch leaves nothing behind. The image takes its name only
// once it is complete and durable.
func (in installer) fetch(ctx context.Context, dir, name, binary string, a pins.Artifact) error {
	body, err := artifact.Fetch(ctx, in.client, a.URL, artifact.MaxArtifact)
	if err != nil {
		return err
	}
	defer body.Close()
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), body); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != a.SHA256 {
		return fmt.Errorf("the download's sha256 %s is not the row's %s", got, a.SHA256)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	t, err := unpack(tmp, binary)
	if err != nil {
		return err
	}
	img, err := os.CreateTemp(dir, ".image-*")
	if err != nil {
		return err
	}
	defer os.Remove(img.Name())
	defer img.Close()
	if err := t.WriteExt4File(img, time.Time{}, 0); err != nil {
		return err
	}
	if err := img.Sync(); err != nil {
		return err
	}
	return os.Rename(img.Name(), filepath.Join(dir, name))
}

// unpack reads the artifact f into the tree of a layer, its shape told by content and never
// by URL: a gzip stream or a tar is applied as a layer, anything else is one bare file. Then,
// once, a tree without bin/<binary> whose root holds exactly one regular file and no bin/
// entry has that file become bin/<binary>, mode 0755; the bare file is that case. A tree
// that already holds bin/<binary> is left as it is. Any other shape is refused.
func unpack(f *os.File, binary string) (*rootfs.Tree, error) {
	head := make([]byte, 262)
	n, _ := io.ReadFull(f, head)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	t := rootfs.NewTree()
	if bytes.HasPrefix(head[:n], []byte{0x1f, 0x8b}) || (n == len(head) && string(head[257:262]) == "ustar") {
		if _, err := t.Apply(f, maxLayer); err != nil {
			return nil, err
		}
	} else {
		data, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		if err := t.Put(binary, rootfs.Node{Kind: rootfs.File, Mode: 0o755, Data: data}); err != nil {
			return nil, err
		}
	}
	want := "bin/" + binary
	if t.Lookup(want) != nil {
		return t, nil
	}
	var files []string
	for _, name := range t.Names("/") {
		if t.Lookup(name).Kind == rootfs.File {
			files = append(files, name)
		}
	}
	if len(files) != 1 || t.Lookup("bin") != nil {
		return nil, fmt.Errorf("the artifact holds neither %s nor one file at its root to become it", want)
	}
	t.Lookup(files[0]).Mode = 0o755
	return t, errors.Join(t.Put("bin", rootfs.Node{Kind: rootfs.Dir, Mode: 0o755}), t.Link(files[0], want), t.Remove(files[0]))
}

// point makes the complete image current the agent's layer, keeps previous as the one to
// roll back to, removes any other image, records the result and returns the result line.
func (in installer) point(agent string, row pins.Pin, dir, current, previous, result string) (string, error) {
	if err := writeMarker(dir, "previous", previous); err != nil {
		return "", err
	}
	if err := writeMarker(dir, "current", current); err != nil {
		return "", err
	}
	images, _ := filepath.Glob(filepath.Join(dir, "*.ext4"))
	for _, img := range images {
		if b := filepath.Base(img); b != current && b != previous {
			os.Remove(img)
		}
	}
	v, d := known(row, current)
	if err := in.record(agent, v, d, result); err != nil {
		return "", err
	}
	return agent + " " + v + " " + d[:min(16, len(d))], nil
}

// refuse records a refusal and returns it, named for the agent.
func (in installer) refuse(agent, version, digest string, err error) error {
	return errors.Join(fmt.Errorf("%s: %w", agent, err), in.record(agent, version, digest, "refused"))
}

// updateRecord is one line of <data>/updates.log, in the secret ledger's shape: time first,
// then the fields, then the result: installed, rolled_back or refused.
type updateRecord struct {
	Time    string `json:"time"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Result  string `json:"result"`
}

// record appends one line to the append-only record and makes it durable before it returns.
func (in installer) record(agent, version, digest, result string) error {
	line, _ := json.Marshal(updateRecord{time.Now().UTC().Format(time.RFC3339Nano), agent, version, digest, result})
	if err := os.MkdirAll(in.dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(in.dir, "updates.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return errors.Join(err, f.Sync(), f.Close())
}

// imageName is the file name of a release's layer: its version and the first 16 hex of its digest.
func imageName(version, digest string) string { return version + "-" + digest[:16] + ".ext4" }

// known is the version and digest of the image name: the full digest when the row still names
// the release, the prefix the name carries otherwise.
func known(row pins.Pin, name string) (version, digest string) {
	for _, r := range []*pins.Release{&row.Release, row.Previous} {
		if r == nil {
			continue
		}
		if a, ok := r.Artifacts[runtime.GOARCH]; ok && len(a.SHA256) == 64 && imageName(r.Version, a.SHA256) == name {
			return r.Version, a.SHA256
		}
	}
	stem := strings.TrimSuffix(name, ".ext4")
	i := strings.LastIndex(stem, "-")
	return stem[:max(i, 0)], stem[i+1:]
}

// marker is the image name the marker file names, or "" when there is none.
func marker(dir, which string) string {
	b, err := os.ReadFile(filepath.Join(dir, which))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeMarker points the marker at the image name, through a rename so that a reader sees the
// old name or the new one, or removes the marker when name is empty.
func writeMarker(dir, which, name string) error {
	path := filepath.Join(dir, which)
	if name == "" {
		if err := os.Remove(path); !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.WriteFile(path+".tmp", []byte(name+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
