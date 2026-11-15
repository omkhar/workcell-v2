// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/internal/audit"
)

// logPoll is how often `log -f` looks for new bytes: a plain read from the last offset (A9).
const logPoll = 250 * time.Millisecond

// logs is `workcell log [-f] [--format ocsf] [id]`: it shows the session's record, one line each, and
// for a refused connection the host to allow. The session is id, or the newest run in this directory.
// With -f it keeps showing the record as it is written, until the session is no longer running.
// With --format ocsf every record is one OCSF event instead.
func logs(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	follow := fs.Bool("f", false, "")
	format := fs.String("format", "", "")
	if fs.Parse(args) != nil || fs.NArg() > 1 || (*format != "" && *format != "ocsf") {
		fmt.Fprintln(stderr, "usage: workcell log [-f] [--format ocsf] [id]")
		return 2
	}
	dir, err := logSession(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "workcell log:", err)
		return 2
	}
	cfg, _ := configFile() // "config.toml" when there is no config directory
	if err := showDenies(dir, cfg, *follow, *format == "ocsf", stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "workcell log:", err)
		return 1
	}
	return 0
}

// logSession is the session directory for id, or for "" the newest session run in this directory.
func logSession(id string) (string, error) {
	sessions, err := sessionsPath()
	if err != nil {
		return "", err
	}
	if id == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return newest(sessions, cwd)
	}
	dir := filepath.Join(sessions, id)
	if st, err := os.Stat(dir); !validID(id) || err != nil || !st.IsDir() {
		return "", fmt.Errorf("no session %q: workcell ls lists them", id)
	}
	return dir, nil
}

// showDenies prints what the session's audit.log holds and, with follow, what is added to it until
// the session is not running and the file has no more bytes. A session with no audit.log has none yet.
func showDenies(dir, cfg string, follow, ocsf bool, out, errs io.Writer) error {
	var off int64
	r := denyReader{cfg: cfg, ocsf: ocsf}
	for {
		up, err := running(dir) // asked before the read, so that a stopped session is read to its end
		if err != nil {
			return err
		}
		f, err := os.Open(filepath.Join(dir, audit.LogName))
		if err == nil {
			var data []byte
			if _, err = f.Seek(off, io.SeekStart); err == nil {
				data, err = io.ReadAll(f)
			}
			f.Close()
			if err != nil {
				return err
			}
			off += int64(len(data))
			r.feed(data, out)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if !follow || !up {
			break
		}
		time.Sleep(logPoll)
	}
	if r.malformed > 0 {
		fmt.Fprintf(errs, "%d malformed line(s) in audit.log were not shown\n", r.malformed)
	}
	return nil
}

// denyReader turns the bytes of an audit.log, as they arrive, into one line of text per record: the
// record's own line, or for a refused connection the sentence denyMessage makes. A line the strict
// reader refuses is counted, never printed: it is host-written, but its fields came from the guest.
type denyReader struct {
	cfg       string
	ocsf      bool   // every record is an OCSF event
	pending   []byte // the start of a line whose end has not arrived
	malformed int
}

func (r *denyReader) feed(data []byte, out io.Writer) {
	r.pending = append(r.pending, data...)
	for {
		i := bytes.IndexByte(r.pending, '\n')
		if i < 0 {
			return
		}
		line := string(r.pending[:i])
		r.pending = r.pending[i+1:]
		switch d, ok := audit.ParseLine(line); {
		case !ok:
			r.malformed++
		case r.ocsf:
			out.Write(append(ocsfLine(d), '\n'))
		case d.Event == audit.Connect && d.Result != audit.Allowed:
			fmt.Fprintln(out, denyMessage(d, r.cfg))
		case d.Event == audit.LogFull:
			fmt.Fprintln(out, "log full, later connections were not recorded")
		default:
			fmt.Fprintln(out, line)
		}
	}
}

// denyMessage is one deny line in a sentence: what was refused, and the one thing to do about it.
// The host is guest-chosen bytes for a TLS name, so it is shown only in a form safe to copy.
func denyMessage(d audit.Record, cfg string) string {
	host := audit.SafeHost(d.Host)
	if host == "" { // as printed when it is no remedy
		host = "(invalid)"
	}
	allow := func(entry string) string {
		return fmt.Sprintf("allow it with  workcell run --allow %s  or add %q to [network] allow in %s", entry, entry, cfg)
	}
	switch d.Result {
	case "name_not_allowed", "sni_not_allowed":
		via := map[string]string{"name_not_allowed": "dns", "sni_not_allowed": "tls"}[d.Result]
		if host == "(invalid)" {
			return fmt.Sprintf("denied %s (%s): not a host name, so there is nothing to allow", host, via)
		}
		return fmt.Sprintf("denied %s (%s): %s", host, via, allow(host))
	case "no_sni":
		return "denied a TLS connection with no server name (tls): there is no host name to allow"
	case "port_not_allowed":
		return fmt.Sprintf("denied port %d (tcp): a bare name allows 443 only, and host:%d forwards this port: %s", d.Port, d.Port, allow(fmt.Sprintf("host:%d", d.Port)))
	case "host_mismatch":
		return fmt.Sprintf("denied %s (tls): the request named another host than its TLS name", host)
	}
	return fmt.Sprintf("denied %s port %d: %s", host, d.Port, d.Result)
}

// verify is `workcell verify [id]`: it says whether the session's audit.log is exactly what this
// host wrote (I9), by the seal that only this host's key signs. The session is as for log, and may
// be running.
func verify(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 || (len(args) == 1 && strings.HasPrefix(args[0], "-")) {
		fmt.Fprintln(stderr, "usage: workcell verify [id]")
		return 2
	}
	id := ""
	if len(args) == 1 {
		id = args[0]
	}
	dir, err := logSession(id)
	if err != nil {
		fmt.Fprintln(stderr, "workcell verify:", err)
		return 2
	}
	data, err := dataDir()
	if err == nil {
		var key ed25519.PrivateKey
		if key, err = audit.LoadKey(data); err == nil {
			err = audit.Verify(dir, key.Public().(ed25519.PublicKey))
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "workcell verify:", err)
		return 1
	}
	fmt.Fprintln(stdout, "intact:", filepath.Base(dir))
	return 0
}
