// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"strconv"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/internal/artifact"
	"github.com/omkhar/workcell/v2/internal/channel"
	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/provider"
	"github.com/omkhar/workcell/v2/internal/rootfs"
	rows "github.com/omkhar/workcell/v2/pins"
)

// maxLayer bounds the bytes of tar stream, and of file data, that one provider CLI's artifact may unpack to in memory.
const maxLayer = 1 << 30

// update is `workcell update [--to VERSION | --rollback] [AGENT]`: the host side of a provider CLI's install (A10).
// What may be installed is a pin of the signed channel manifest (I14), or of the row under pins/ when the channel
// is held or no key is trusted: fetched on the host by its URL, refused unless its sha256 is the pin's (B8), and
// unpacked into a layer, an ext4 image under the data directory that a session attaches read-only. A `current`
// marker names the layer once the image is complete; the one it replaces stays as `previous`, which --rollback goes back to without fetching.
func update(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	to := fs.String("to", "", "")
	rollback := fs.Bool("rollback", false, "")
	if fs.Parse(args) != nil || fs.NArg() > 1 || (*to != "" && *rollback) || (fs.NArg() == 0 && (*to != "" || *rollback)) {
		fmt.Fprintln(stderr, "usage: workcell update [--to VERSION | --rollback] [AGENT]\n  installs the pinned release of a provider CLI, or of every provider; --to takes the current or the previous release, --rollback the layer kept from before")
		return 2
	}
	in, err := newInstaller()
	provs, perr := provider.All()
	if fs.NArg() == 1 {
		if provs = slices.DeleteFunc(provs, func(p provider.Provider) bool { return p.Name != fs.Arg(0) }); len(provs) == 0 && perr == nil {
			perr = fmt.Errorf("no provider named %q", fs.Arg(0))
		}
	}
	if err = errors.Join(err, perr); err != nil {
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

// installer is what update works with: the data directory, the rows under pins/, the client that fetches, which
// follows no redirect (a 3xx is a refusal), the channel's URL, "" when nothing is fetched, the keys trusted to sign it and the user's cool-off (B10).
type installer struct {
	dir     string
	rows    []pins.Pin
	client  *http.Client
	channel string
	keys    []channel.Key
	cooloff time.Duration
}

// newInstaller reads the user's [update] table (B10): the channel is fetched unless it is "hold" or no
// key is trusted, the table's alone when it gives one, else the built-in ones; ca's certificates alone are the roots.
func newInstaller() (in installer, err error) {
	in = installer{client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, keys: channel.Keys}
	file, err := configFile()
	var p policy.Policy
	if err == nil {
		p, err = policy.Read(file)
	}
	if err == nil {
		in.rows, err = rows.All()
	}
	if err == nil {
		in.dir, err = dataDir()
	}
	if err != nil {
		return in, err
	}
	u := p.Update
	in.cooloff = u.Cooloff
	if u.Key != nil {
		in.keys = []channel.Key{{Public: u.Key, NotAfter: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}}
	}
	switch {
	case u.Channel == "hold" || len(in.keys) == 0:
	case u.Channel == "" || u.Channel == "stable": // where the project publishes (ADR-004)
		in.channel = "https://omkhar.github.io/workcell/channel.json"
	default:
		in.channel = u.Channel
	}
	if u.CA != "" {
		pem, err := os.ReadFile(u.CA)
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return in, fmt.Errorf("%s: [update] ca %s: %w", file, u.CA, cmp.Or(err, errors.New("no certificate in it")))
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{RootCAs: pool}
		in.client.Transport = t
	}
	return in, nil
}

// update brings the provider p to its current pin, to the pin to names, or back to the layer kept from before, and
// returns the result line: agent, version, digest prefix. The pins come from the channel manifest when there is one to fetch, else from the row's own.
func (in installer) update(ctx context.Context, p provider.Provider, to string, rollback bool) (string, error) {
	dir := filepath.Join(in.dir, "layers", p.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	row, err := in.row(p)
	if err != nil {
		return "", in.refuse(p.Name, "", "", err)
	}
	cur, prev := marker(dir, "current"), marker(dir, "previous")
	if rollback {
		if cur == "" || prev == "" {
			return "", in.refuse(p.Name, "", "", errors.New("there is no earlier layer to roll back to"))
		}
		return in.point(p.Name, dir, prev, cur, "rolled_back")
	}
	m := channel.Build([]pins.Pin{row}, time.Now())
	if in.channel != "" {
		fetched, err := in.manifest(ctx)
		if err != nil {
			return "", in.refuse(p.Name, to, "", err)
		}
		m = *fetched
	}
	pin, err := choose(channel.Select(&m, row.Name, runtime.GOARCH), to, in.cooloff, time.Now())
	if err != nil {
		return "", in.refuse(p.Name, to, "", err)
	}
	switch name := imageName(pin.Version, pin.SHA256); name {
	case cur:
		return p.Name + " " + pin.Version + " " + pin.SHA256[:16], nil
	case prev:
		return in.point(p.Name, dir, prev, cur, "rolled_back")
	default:
		if err := in.fetch(ctx, dir, name, p.Binary, pin); err != nil {
			return "", in.refuse(p.Name, pin.Version, pin.SHA256, err)
		}
		return in.point(p.Name, dir, name, cur, "installed")
	}
}

// row is the pins/ row of p: the pin its install names, when it is installed as a binary.
func (in installer) row(p provider.Provider) (pins.Pin, error) {
	i := slices.IndexFunc(in.rows, func(r pins.Pin) bool { return r.Name == p.Install.Pin })
	switch {
	case p.Install.Method != "binary":
		return pins.Pin{}, fmt.Errorf("provider %s is installed by %s; update installs binaries only", p.Name, p.Install.Method)
	case i < 0:
		return pins.Pin{}, fmt.Errorf("provider %s names pin %s, which has no row under pins/", p.Name, p.Install.Pin)
	case in.rows[i].Version == "":
		return pins.Pin{}, fmt.Errorf("provider %s names pin %s, whose row pins no release yet", p.Name, p.Install.Pin)
	}
	return in.rows[i], nil
}

// manifest fetches channel.json once, at most channel.MaxBytes, and verifies it against the keys
// and the last serial seen, kept in <data>/channel.serial, which advances only once a manifest
// verified (I14) and on any failure is untouched.
func (in installer) manifest(ctx context.Context) (*channel.Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	body, err := artifact.Fetch(ctx, in.client, in.channel, channel.MaxBytes)
	var raw []byte
	if err == nil {
		raw, err = io.ReadAll(body)
		body.Close()
	}
	last, _ := strconv.ParseInt(marker(in.dir, "channel.serial"), 10, 64) // absent, or not a number, is 0
	var m *channel.Manifest
	if err == nil {
		m, err = channel.Verify(raw, in.keys, time.Now(), last)
	}
	if err != nil {
		return nil, fmt.Errorf("channel: %w", err)
	}
	return m, writeMarker(in.dir, "channel.serial", strconv.FormatInt(m.Serial, 10))
}

// choose is the candidate to install: with to, the one of that version, any other version refused; without,
// the first, or the previous one while the user's cool-off (B10) still holds the first at now, or a refusal when there is none.
func choose(cands []channel.Pin, to string, cooloff time.Duration, now time.Time) (channel.Pin, error) {
	if to != "" {
		if i := slices.IndexFunc(cands, func(c channel.Pin) bool { return c.Version == to }); i >= 0 {
			return cands[i], nil
		}
		return channel.Pin{}, fmt.Errorf("version %s is in neither pins nor previous", to)
	}
	if len(cands) > 0 && now.Before(time.Unix(cands[0].Released, 0).Add(cooloff)) {
		cands = cands[1:]
	}
	if len(cands) == 0 {
		return channel.Pin{}, fmt.Errorf("nothing is pinned for %s that the %s cool-off lets in", runtime.GOARCH, cooloff)
	}
	return cands[0], nil
}

// fetch downloads the pin into dir as the image name, through its digest check (B8): the bytes go to a temporary
// file as they are hashed, and are unpacked only once the digest is the pin's, a mismatch leaving nothing behind; the image, written over the download, takes its name once complete and durable.
func (in installer) fetch(ctx context.Context, dir, name, binary string, pin channel.Pin) error {
	body, err := artifact.Fetch(ctx, in.client, pin.URL, artifact.MaxArtifact)
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
	if got := hex.EncodeToString(h.Sum(nil)); got != pin.SHA256 {
		return fmt.Errorf("the download's sha256 %s is not the pin's %s", got, pin.SHA256)
	}
	t, err := unpack(tmp, binary)
	if err != nil {
		return err
	}
	if err := errors.Join(tmp.Truncate(0), t.WriteExt4File(tmp, time.Time{}, 0), tmp.Sync()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// unpack reads the artifact f into the tree of a layer, its shape told by content and never by
// URL: a gzip stream or a tar is applied as a layer, anything else is one bare file. Then, once, a
// tree without bin/<binary> whose root holds exactly one regular file and no bin/ entry has that
// file become bin/<binary>, mode 0755; the bare file is that case. Any other shape is refused.
func unpack(f *os.File, binary string) (*rootfs.Tree, error) {
	head := make([]byte, 262)
	n, _ := f.ReadAt(head, 0)
	r := io.NewSectionReader(f, 0, 1<<62) // from the start, wherever f was left
	t := rootfs.NewTree()
	if bytes.HasPrefix(head[:n], []byte{0x1f, 0x8b}) || (n == len(head) && string(head[257:262]) == "ustar") {
		if _, err := t.Apply(r, maxLayer); err != nil {
			return nil, err
		}
	} else {
		data, err := io.ReadAll(r)
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
	files := slices.DeleteFunc(t.Names("/"), func(name string) bool { return t.Lookup(name).Kind != rootfs.File })
	if len(files) != 1 || t.Lookup("bin") != nil {
		return nil, fmt.Errorf("the artifact holds neither %s nor one file at its root to become it", want)
	}
	t.Lookup(files[0]).Mode = 0o755
	return t, errors.Join(t.Put("bin", rootfs.Node{Kind: rootfs.Dir, Mode: 0o755}), t.Link(files[0], want), t.Remove(files[0]))
}

// point makes the complete image current, keeps previous to roll back to, removes any other image, records and reports.
func (in installer) point(agent, dir, current, previous, result string) (string, error) {
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
	stem := strings.TrimSuffix(current, ".ext4") // the version and the digest the image is named for
	i := strings.LastIndex(stem, "-")
	v, d := stem[:max(i, 0)], stem[i+1:]
	if err := in.record(agent, v, d, result); err != nil {
		return "", err
	}
	return agent + " " + v + " " + d[:min(16, len(d))], nil
}

// refuse records a refusal and returns it, named for the agent.
func (in installer) refuse(agent, version, digest string, err error) error {
	return errors.Join(fmt.Errorf("%s: %w", agent, err), in.record(agent, version, digest, "refused"))
}

// updateRecord is one line of <data>/updates.log: time first, then the fields, then installed, rolled_back or refused.
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
	f, err := os.OpenFile(filepath.Join(in.dir, "updates.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return errors.Join(err, f.Sync(), f.Close())
}

// imageName is the file name of a pin's layer: its version and its digest.
func imageName(version, digest string) string { return version + "-" + digest + ".ext4" }

// marker is the image name the marker file names, or "" when there is none.
func marker(dir, which string) string {
	b, _ := os.ReadFile(filepath.Join(dir, which))
	return strings.TrimSpace(string(b))
}

// writeMarker points the marker at the image name, "" for none, through a rename: a reader sees the old name or the new.
func writeMarker(dir, which, name string) error {
	path := filepath.Join(dir, which)
	if err := os.WriteFile(path+".tmp", []byte(name+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
