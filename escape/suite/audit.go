// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The I9 probe is root in the guest and knows where the host keeps the
// session's record, as an attacker who read the product's source does. It
// goes for the record by that path, through the directory holding it, and
// through everything the guest writes that the host collects. In the control
// sandbox the guest's root is the host's, so the path is reachable; in a real
// guest it is not. The judge reads the record on the host, before and after,
// and the guest's word counts for nothing.

// forgedMarker begins the record the forge probe plants. No judge passes it
// as an argument, so a record holding it was written by the guest.
const forgedMarker = "forged-record-"

// auditProbe does args[0] to the record at args[1]: forge plants a record
// (also in args[2], the export, when that is set), suppress sends the path
// to /dev/null, truncate empties it, and noop is a run that only records.
func auditProbe(args []string) Result {
	if len(args) < 2 {
		return Result{Status: "error", Detail: "want a verb and the record's path"}
	}
	verb, path := args[0], args[1]
	switch verb {
	case "noop":
		return Result{Status: "ran", Detail: "nothing tried"}
	case "forge":
		token := newToken()
		line := fmt.Sprintf(`{"event":"connect","host":"%s%s.escape.test","verdict":"allow"}`+"\n", forgedMarker, token)
		n := 0
		if f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0); err == nil { // the record itself
			if _, err := f.WriteString(line); err == nil {
				n++
			}
			f.Close()
		}
		places := []string{filepath.Join(filepath.Dir(path), "audit.log"), filepath.Join(filepath.Dir(path), filepath.Base(path)+".1")}
		if len(args) > 2 && args[2] != "" {
			places = append(places, filepath.Join(args[2], filepath.Base(path)))
		}
		for _, p := range places { // beside it, and in the export
			if err := os.WriteFile(p, []byte(line), 0o644); err == nil {
				n++
			}
		}
		os.Stderr.WriteString(line) // and in what the host collects of the guest's output
		return Result{Status: "tried", Detail: fmt.Sprintf("wrote=%d token=%s", n, token)}
	case "suppress":
		if err := os.Rename(path, path+".moved"); err != nil {
			return Result{Status: "tried", Detail: "rename: " + short(err)}
		}
		if err := os.Symlink("/dev/null", path); err != nil {
			return Result{Status: "tried", Detail: "symlink: " + short(err)}
		}
		return Result{Status: "tried", Detail: "the record's path now leads to /dev/null"}
	case "truncate":
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return Result{Status: "tried", Detail: "truncate: " + short(err)}
		}
		f.Close()
		return Result{Status: "tried", Detail: "truncated the record to nothing"}
	}
	return Result{Status: "error", Detail: "unknown verb " + verb}
}

// auditJudge reads the record, has the guest attack it as verb says, runs
// the guest once more, and reads the record again. Every record seen before
// must still be there, in order, verify must still accept the record, a run
// recorded before the attack must still be recorded after it, and no record
// may hold what the guest planted.
func auditJudge(verb string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		path, before, err := s.Audit(ctx)
		if err != nil {
			return false, "", err
		}
		if len(before) == 0 {
			return false, "", errors.New("the record holds nothing before the guest ran, not even the session's start")
		}
		r, err := s.Run(verb, path, s.Guest)
		if err != nil {
			return false, "", err
		}
		say := fmt.Sprintf(" (guest says %s: %s)", r.Status, r.Detail)
		_, mid, err := s.Audit(ctx)
		if err != nil {
			return false, "the record cannot be read after the guest's " + verb + ": " + err.Error() + say, nil
		}
		if _, err := s.Run("noop", path); err != nil {
			return false, "", err
		}
		_, after, err := s.Audit(ctx)
		if err != nil {
			return false, "the record cannot be read after the guest's " + verb + ": " + err.Error() + say, nil
		}
		for i, rec := range before {
			if i >= len(after) || after[i] != rec {
				return false, fmt.Sprintf("record %d of %d is gone or changed after the guest's %s%s", i+1, len(before), verb, say), nil
			}
		}
		if len(mid) > len(before) && len(after) <= len(mid) {
			return false, "the run after the guest's " + verb + " added no record, where the run before it did" + say, nil
		}
		if err := s.Verify(ctx); err != nil {
			return false, "verify rejects the record after the guest's " + verb + ": " + err.Error() + say, nil
		}
		for i, rec := range after {
			if strings.Contains(rec, forgedMarker) {
				return false, fmt.Sprintf("record %d is one the guest wrote: %.80s%s", i+1, rec, say), nil
			}
		}
		return true, fmt.Sprintf("%d records before, %d after, all kept, verify accepts%s", len(before), len(after), say), nil
	}
}

// offlineJudge edits the record on the host after the fact, as edit says,
// and expects verify to reject it. First the record, with one run in it,
// must pass verify as the product wrote it, so that a verify which checks
// nothing cannot pass by having nothing to check.
func offlineJudge(edit string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		path, _, err := s.Audit(ctx)
		if err != nil {
			return false, "", err
		}
		if _, err := s.Run("noop", path); err != nil {
			return false, "", err
		}
		if err := s.Verify(ctx); err != nil {
			return false, "", fmt.Errorf("verify rejects the record before any edit: %w", err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return false, "", err
		}
		lines := bytes.SplitAfter(b, []byte("\n"))
		if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
			lines = lines[:len(lines)-1]
		}
		var edited []byte
		switch edit {
		case "drop": // the middle record
			if len(lines) < 3 {
				return false, "", fmt.Errorf("the record holds %d lines; dropping one needs three", len(lines))
			}
			edited = bytes.Join(append(lines[:len(lines)/2:len(lines)/2], lines[len(lines)/2+1:]...), nil)
		case "alter": // one byte in the middle
			edited = bytes.Clone(b)
			i := len(b) / 2
			for i < len(b) && (b[i] < '0' || b[i] > 'z') {
				i++
			}
			if i >= len(b) {
				return false, "", errors.New("the record has no byte to alter")
			}
			edited[i] = '0' + (edited[i]+1)%('z'-'0')
		case "truncate": // the tail
			edited = b[:len(b)/2]
		case "append": // a copy of the last record
			if len(lines) == 0 {
				return false, "", errors.New("the record holds no line to copy")
			}
			edited = append(bytes.Clone(b), lines[len(lines)-1]...)
		case "swap": // the two middle records change places, both whole
			if len(lines) < 2 {
				return false, "", fmt.Errorf("the record holds %d lines; swapping two needs two", len(lines))
			}
			i := len(lines) / 2
			if bytes.Equal(lines[i-1], lines[i]) {
				return false, "", errors.New("the two middle records are the same byte for byte; nothing to swap")
			}
			edited = bytes.Join([][]byte{bytes.Join(lines[:i-1], nil), lines[i], lines[i-1], bytes.Join(lines[i+1:], nil)}, nil)
		default:
			return false, "", errors.New("unknown edit " + edit)
		}
		if err := os.WriteFile(path, edited, 0o600); err != nil {
			return false, "", err
		}
		err = s.Verify(ctx)
		if err == nil {
			return false, fmt.Sprintf("verify accepts the record after the %s edit (%d bytes before, %d after)", edit, len(b), len(edited)), nil
		}
		return true, fmt.Sprintf("verify rejects the record after the %s edit: %s", edit, err), nil
	}
}

// connectProbe opens TLS from the guest to the allowed name and to the
// denied one, each at the address the judge gave, and says only how each
// went: never the names. Both sandboxes may keep the guest's words, its
// command line and its output, so the names come in hex and leave as
// "served", "refused" and the like; a record naming one can then only be
// the host's own account of the connection. args: allowed name in hex, its
// address, denied name in hex, its address.
func connectProbe(args []string) Result {
	if len(args) != 4 {
		return Result{Status: "error", Detail: "want allowed name in hex, address, denied name in hex, address"}
	}
	var out []string
	status := "unreached"
	for i, label := range []string{"allowed", "denied"} {
		name, err := hex.DecodeString(args[2*i])
		if err != nil {
			return Result{Status: "error", Detail: label + " name is not hex"}
		}
		t := targets{addrs: map[string]string{string(name): args[2*i+1]}}
		r := report(fetch(t.get(string(name), "/recorded"), t.addrs, &tls.Config{}, false))
		if r.Status == "served" {
			status = "served"
		}
		out = append(out, label+"="+r.Status)
	}
	return Result{Status: status, Detail: strings.Join(out, " ")}
}

// recordedJudge serves a canary for the allowed name and one for the denied
// name, has the guest try both, and expects the records the run added to
// name each: a connection attempt the host let through and one it refused
// are both recorded (I9). The names reach the guest in hex and come back
// as verdicts, so a record naming one is the host's, not the guest's echo.
func recordedJudge(ctx context.Context, s Session) (bool, string, error) {
	allowed, denied := &canary{name: s.Allow[0]}, &canary{name: s.Deny[0]}
	ns, stop, err := serveTwo(ctx, s, nil, allowed, denied)
	if err != nil {
		return false, "", err
	}
	defer ns.stop()
	defer stop()
	_, before, err := s.Audit(ctx)
	if err != nil {
		return false, "", err
	}
	r, err := s.Run(hex.EncodeToString([]byte(allowed.name)), allowed.addr, hex.EncodeToString([]byte(denied.name)), denied.addr)
	if err != nil {
		return false, "", err
	}
	say := fmt.Sprintf(" (guest says %s: %s)", r.Status, r.Detail)
	_, after, err := s.Audit(ctx)
	if err != nil {
		return false, "", err
	}
	if len(after) < len(before) {
		return false, fmt.Sprintf("%d records before the run, %d after%s", len(before), len(after), say), nil
	}
	added := after[len(before):]
	for _, name := range []string{allowed.name, denied.name} {
		if !slices.ContainsFunc(added, func(rec string) bool { return strings.Contains(rec, name) }) {
			return false, fmt.Sprintf("none of the %d records the run added names %s%s", len(added), name, say), nil
		}
	}
	return true, fmt.Sprintf("the run added %d records, naming both the allowed and the denied connection%s", len(added), say), nil
}
