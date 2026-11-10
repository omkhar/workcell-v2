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
	"sync"
	"time"

	"github.com/omkhar/workcell/v2/internal/artifact"
	"github.com/omkhar/workcell/v2/internal/channel"
	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/provider"
	"github.com/omkhar/workcell/v2/internal/rootfs"
	rows "github.com/omkhar/workcell/v2/pins"
)

// maxLayer bounds the bytes of tar stream, and of file data, that one provider CLI's artifact may unpack to in memory; channelBound is how long a fetch at a
// session start may take: the day's check, and the install of what it kept.
const (
	maxLayer     = 1 << 30
	channelBound = 10 * time.Minute
)

// update is `workcell update [--to VERSION | --rollback] [AGENT]`: the host side of a provider CLI's install (A10). What may be installed is a pin of the
// signed channel manifest (I14), or of the row under pins/ when the channel is held or no key is trusted: fetched on the host by its URL, refused unless its
// sha256 is the pin's (B8), and unpacked into a layer, an ext4 image under the data directory that a session attaches read-only. A `current` marker names the
// layer once the image is complete; the one it replaces stays as `previous`, which --rollback goes back to without fetching.
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute) // one bound for the invocation: a stalled upstream cannot hang it
	defer cancel()
	manifest := sync.OnceValues(func() (*channel.Manifest, error) { _, m, err := in.manifest(ctx); return m, err }) // channel.json is fetched and verified once, however many providers install
	rc := 0
	for _, p := range provs {
		if _, err := in.row(p); err != nil && fs.NArg() == 0 {
			continue
		}
		line, err := in.update(ctx, p, manifest, *to, *rollback)
		if err != nil {
			fmt.Fprintln(stderr, "workcell update:", err)
			rc = 1
			continue
		}
		fmt.Fprintln(stdout, line)
	}
	return rc
}

// installer is what update works with: the data directory, the rows under pins/, the client that fetches (an artifact through pins.Redirect, channel.json
// following no redirect), the channel's URL, "" when nothing is fetched, the keys trusted to sign it and the user's cool-off (B10).
type installer struct {
	dir     string
	rows    []pins.Pin
	client  *http.Client
	channel string
	keys    []channel.Key
	cooloff time.Duration
}

// newInstaller reads the user's [update] table (B10): the channel is fetched unless it is "hold" or no key is trusted, the table's alone when it gives one,
// else the built-in ones; ca's certificates alone are the roots.
func newInstaller() (in installer, err error) {
	in = installer{client: &http.Client{}, keys: channel.Keys}
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

// update brings the provider p to its current pin, to the pin to names, or back to the layer kept from before, and returns the result line: agent, version,
// digest prefix. The pins come from the channel manifest, fetched by manifest when there is one to fetch, else from the row's own.
func (in installer) update(ctx context.Context, p provider.Provider, manifest func() (*channel.Manifest, error), to string, rollback bool) (string, error) {
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
		fetched, err := manifest()
		if err != nil {
			return "", in.refuse(p.Name, to, "", err)
		}
		m = *fetched
	}
	pin, err := choose(channel.Select(&m, row.Name, runtime.GOARCH), to, in.cooloff, time.Now())
	if err != nil {
		return "", in.refuse(p.Name, to, "", err)
	}
	switch name := pin.Version + "-" + pin.SHA256 + ".ext4"; name { // the file name of a pin's layer: its version and its digest
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

// manifest fetches channel.json, at most channel.MaxBytes and following no redirect (a 3xx is a refusal), and verifies it (verify); it returns the bytes too,
// for the daily check to keep.
func (in installer) manifest(ctx context.Context) ([]byte, *channel.Manifest, error) {
	c := http.Client{Transport: in.client.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, err := artifact.Fetch(ctx, &c, in.channel, "", channel.MaxBytes)
	var raw []byte
	if err == nil {
		raw, err = io.ReadAll(body)
		body.Close()
	}
	var m *channel.Manifest
	if err == nil {
		m, err = in.verify(raw, time.Now())
	}
	if err != nil {
		return nil, nil, fmt.Errorf("channel: %w", err)
	}
	return raw, m, nil
}

// verify is channel.Verify of raw at now against the keys and the last serial seen, kept in <data>/channel.serial, which advances only once a manifest verified
// (I14) and on any failure is untouched.
func (in installer) verify(raw []byte, now time.Time) (*channel.Manifest, error) {
	last, _ := strconv.ParseInt(marker(in.dir, "channel.serial"), 10, 64) // absent, or not a number, is 0
	m, err := channel.Verify(raw, in.keys, now, last)
	if err != nil {
		return nil, err
	}
	return m, writeMarker(in.dir, "channel.serial", strconv.FormatInt(m.Serial, 10))
}

// daily is the day's channel check (B9) at a session start: the first of a UTC day, by <data>/channel.day, fetches channel.json once, in a goroutine the
// session never awaits (A9: it dies with the process), and keeps a manifest that verifies as <data>/channel.next for the next start to apply; later starts that
// day, and a held channel, fetch nothing. It says whether a check started.
func (in installer) daily(now time.Time) bool {
	day := now.UTC().Format("2006-01-02")
	if in.channel == "" || marker(in.dir, "channel.day") == day || writeMarker(in.dir, "channel.day", day) != nil {
		return false
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), channelBound)
		defer cancel()
		if raw, _, err := in.manifest(ctx); err == nil {
			_ = writeMarker(in.dir, "channel.next", string(raw))
		}
	}()
	return true
}

// apply is what a session start makes of the manifest the last daily check kept (B9): <data>/channel.next, removed first whatever follows, is verified again
// and its pin installed for each provider with a row, as the verb does, except that a pin whose image is the one marked failed is skipped (B10); each result or
// error is one line on stderr, and the session goes on.
func (in installer) apply(provs []provider.Provider, stderr io.Writer) {
	raw := marker(in.dir, "channel.next")
	if os.Remove(filepath.Join(in.dir, "channel.next")); raw == "" || in.channel == "" {
		return
	}
	m, err := in.verify([]byte(raw), time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "workcell: channel:", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), channelBound)
	defer cancel()
	for _, p := range provs {
		row, err := in.row(p)
		if err != nil {
			continue
		}
		pin, err := choose(channel.Select(m, row.Name, runtime.GOARCH), "", in.cooloff, time.Now())
		if err == nil && pin.Version+"-"+pin.SHA256+".ext4" == marker(filepath.Join(in.dir, "layers", p.Name), "failed") {
			continue
		}
		line, err := in.update(ctx, p, func() (*channel.Manifest, error) { return m, nil }, "", false)
		if err != nil {
			line = err.Error()
		}
		fmt.Fprintln(stderr, "workcell: update:", line)
	}
}

// fail is the self-rollback (B10): the command's binary is a provider's whose layer is current, and the init could not start it, so that image is named in
// layers/<agent>/failed, which apply skips until its pin changes, and current goes back to the previous layer by itself, nothing fetched and no manifest read;
// with no previous, the next session boots without the layer. One record line, "failed", names the layer set aside. With no installer (startup), nothing.
func (in installer) fail(binary string, stderr io.Writer) {
	provs, _ := provider.All() // startup reported an error here already
	for _, p := range provs {
		dir := filepath.Join(in.dir, "layers", p.Name)
		cur := marker(dir, "current")
		if in.dir == "" || p.Binary != binary || cur == "" {
			continue
		}
		v, d := parse(cur)
		err := writeMarker(dir, "failed", cur)
		if err == nil {
			_, err = in.point(p.Name, dir, marker(dir, "previous"), "", "")
		}
		if err = errors.Join(err, in.record(p.Name, v, d, "failed")); err != nil {
			fmt.Fprintln(stderr, "workcell: update:", err)
		}
		fmt.Fprintf(stderr, "workcell: update: %s %s could not run, so its layer is set aside; workcell update %s installs it again\n", p.Name, v, p.Name)
	}
}

// startup is the channel's part of a session start (B9), each step best-effort and an error one line on stderr: the manifest the last daily check kept is
// applied, then the day's check starts. It returns the installer, for fail after the session.
func startup(stderr io.Writer) installer {
	in, err := newInstaller()
	provs, perr := provider.All()
	if err = errors.Join(err, perr); err != nil {
		fmt.Fprintln(stderr, "workcell: channel:", err)
		return installer{}
	}
	in.apply(provs, stderr)
	in.daily(time.Now())
	return in
}

// choose is the candidate to install: with to, the one of that version, any other version refused; without, the first, or the previous one while the user's
// cool-off (B10) still holds the first at now, or a refusal when there is none.
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

// fetch downloads the pin into dir as the image name, through its digest check (B8): the bytes go to a temporary file as they are hashed, and are unpacked only
// once the digest is the pin's, a mismatch leaving nothing behind; the image, written over the download, takes its name once complete and durable.
func (in installer) fetch(ctx context.Context, dir, name, binary string, pin channel.Pin) error {
	body, err := artifact.Fetch(ctx, in.client, pin.URL, "", artifact.MaxArtifact)
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

// unpack reads the artifact f into the tree of a layer, its shape told by content and never by URL: a gzip stream or a tar is applied as a layer, anything else
// is one bare file. Then, once, a tree without bin/<binary> whose root holds exactly one regular file and no bin/ entry has that file become bin/<binary>, mode
// 0755; the bare file is that case. Any other shape is refused.
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

// point makes the complete image current, keeps previous to roll back to, removes any other image, records the result when there is one and reports.
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
	v, d := parse(current)
	if result != "" {
		if err := in.record(agent, v, d, result); err != nil {
			return "", err
		}
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

// parse is the version and the digest an image is named for.
func parse(name string) (version, digest string) {
	stem := strings.TrimSuffix(name, ".ext4")
	i := strings.LastIndex(stem, "-")
	return stem[:max(i, 0)], stem[i+1:]
}

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
