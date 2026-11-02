// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64

package macos

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// cached returns os.UserCacheDir()/workcell-spike/<name>, downloading url
// there first if the file is missing or its SHA-256 is not the pinned one.
// The digest is logged before it is compared, on every use.
func cached(t *testing.T, url, name, want string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "workcell-spike")
	path := filepath.Join(dir, name)
	if got, err := sha256File(path); err == nil {
		t.Logf("macos sha256 %s=%s cached=true", name, got)
		if got == want {
			return path, nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	c := http.Client{Timeout: 3 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err = errors.Join(err, f.Close()); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	t.Logf("macos sha256 %s=%s cached=false", name, got)
	if got != want {
		return "", fmt.Errorf("%s: sha256 %s, pinned %s", name, got, want)
	}
	return path, os.Rename(f.Name(), path)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func goBuild(t *testing.T, out, pkg string, env ...string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, module+pkg)
	cmd.Env = append(os.Environ(), env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s %v: %v\n%s", pkg, env, err, b)
	}
}

// run is a tool's combined output, bounded in time; errors are part of the answer.
func run(limit time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(b), err
}

// links is what otool -L says a Mach-O loads, or the ELF's DT_NEEDED list.
func links(path string) (all, foreign string) {
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		libs, _ := f.ImportedLibraries()
		return "elf:" + orNone(libs), "none"
	}
	out, _ := run(time.Minute, "otool", "-arch", "arm64", "-L", path)
	return otoolLinks(out)
}

// signature is the signing authority (or "adhoc") and the flags codesign reports.
func signature(path string) string {
	out, _ := run(time.Minute, "codesign", "-dvv", path)
	auth, flags, team := "none", "none", "none"
	for _, l := range strings.Split(out, "\n") {
		if a, ok := strings.CutPrefix(l, "Authority="); ok && auth == "none" {
			auth = strings.ReplaceAll(a, " ", "_")
		}
		if v, ok := strings.CutPrefix(l, "TeamIdentifier="); ok {
			team = v
		}
		if _, f, ok := strings.Cut(l, "flags="); ok {
			flags, _, _ = strings.Cut(f, " ")
		}
	}
	return "authority=" + auth + " team=" + team + " flags=" + flags
}

// procs lists this user's processes as "pid ppid path" (read only, never signalled).
func procs() []string {
	out, _ := run(time.Minute, "ps", "-axo", "pid=,ppid=,uid=,comm=")
	var mine []string
	uid := strconv.Itoa(os.Getuid())
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 4 && f[2] == uid {
			mine = append(mine, f[0]+" "+f[1]+" "+strings.Join(f[3:], " "))
		}
	}
	return mine
}

// count is how many of this user's processes have an executable named base.
func count(base string) int {
	n := 0
	for _, p := range procs() {
		if f := strings.Fields(p); filepath.Base(f[len(f)-1]) == base {
			n++
		}
	}
	return n
}

// holders are the pids that have path open, by lsof.
func holders(path string) []string {
	out, _ := run(30*time.Second, "lsof", "-t", "--", path)
	return strings.Fields(out)
}

func size(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return fi.Size()
}

// firstLine is the first line of a tool's output, with blanks turned to underscores.
func firstLine(out string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	return strings.ReplaceAll(l, " ", "_")
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
