// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The provider layer row (I7). The host installs an agent from an upstream
// the judge serves on its own loopback (SPEC T8), as `workcell update` does;
// root in the guest does what it can to the layer the session runs it from
// (hijack), and a second session must run the version the host installed
// from a layer whose every file is as it was, the image on the host too.
// hijacked is what the guest's own agent would print.
const layerAgent, layerVersion, hijacked = "claude", "9.9.9", "6.6.6"

// layerJudge serves the agent as far as the row cares, a tar holding
// bin/<agent>, an executable shell script that prints the version, has the
// host install it, and compares what two sessions see.
func layerJudge(ctx context.Context, s Session) (bool, string, error) {
	cfg, err := certificate("127.0.0.1")
	if err != nil {
		return false, "", err
	}
	src, err := serve(cfg)
	if err != nil {
		return false, "", err
	}
	defer src.stop()
	var art bytes.Buffer
	tw, body := tar.NewWriter(&art), []byte("#!/bin/sh\necho "+layerVersion+"\n")
	tw.WriteHeader(&tar.Header{Name: "bin/" + layerAgent, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	src.set("/"+layerAgent+".tar", whole(art.Bytes()))
	image, err := s.Install(ctx, sandbox.Layer{Agent: layerAgent, Version: layerVersion, URL: src.url + "/" + layerAgent + ".tar", Artifact: art.Bytes()})
	if err != nil {
		return false, "", err
	}
	before, err := fileSum(image)
	if err != nil {
		return false, "", err
	}
	r, err := s.Run("attack", layerAgent, hijacked)
	if err != nil {
		return false, "", err
	}
	if one := fields(r.Detail); one["version"] != layerVersion {
		return false, "", fmt.Errorf("the first session did not run the installed agent (%s)", says(r))
	}
	two, err := s.Another()
	var r2 Result
	if err == nil {
		r2, err = two.Run("check", layerAgent, hijacked)
	}
	var after string
	if err == nil {
		after, err = fileSum(image)
	}
	both := fmt.Sprintf("second session: %s (first session: %s)", r2.Detail, r.Detail)
	one, other := fields(r.Detail), fields(r2.Detail)
	switch {
	case err != nil:
		return false, "", err
	case before != after:
		return false, "the layer image on the host changed under the session; " + both, nil
	case other["version"] != layerVersion:
		return false, "the second session did not run the version the host installed; " + both, nil
	case other["hash"] != one["hash"]:
		return false, "the second session saw a layer the first changed; " + both, nil
	}
	return true, both, nil
}

// fileSum is the hex SHA-256 of the file at path, "" for no path.
func fileSum(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	return fmt.Sprintf("%x", sha256.Sum256(b)), err
}

// fields reads a detail of key=value words.
func fields(detail string) map[string]string {
	out := map[string]string{}
	for _, f := range strings.Fields(detail) {
		if k, v, ok := strings.Cut(f, "="); ok {
			out[k] = v
		}
	}
	return out
}

// layerProbe finds the agent on PATH, runs `<agent> --version`, hashes
// every file of its layer (the parent of the binary's directory), and, as
// "attack", tries as root to make the agent print the version given, then
// says what the agent prints afterwards. args: verb, agent, version.
func layerProbe(args []string) Result {
	if len(args) != 3 {
		return Result{Status: "error", Detail: "want attack|check, agent and version"}
	}
	path, err := exec.LookPath(args[1])
	if err != nil {
		return Result{Status: "missing", Detail: "version=none " + short(err)}
	}
	root := filepath.Dir(filepath.Dir(path))
	detail := "version=" + output(path, "--version") + " hash=" + treeSum(root)
	if args[0] == "attack" {
		detail += " " + hijack(path, root, []byte("#!/bin/sh\necho "+args[2]+"\n")) + " runs=" + output(path, "--version")
	}
	return Result{Status: "tried", Detail: detail}
}

// hijack tries every way root has to change the layer at root, whose
// binary is path: a write, an unlink and a fresh file, a new file beside
// it, a remount as writable, a write to the block device behind the mount
// and a fresh writable mount of it, with the write wherever a way opened.
// The device is only ever one behind a read-only mount at root itself: the
// layer's own, never the test host's disk.
func hijack(path, root string, body []byte) string {
	write := func(p string) string { return "write=" + status(os.WriteFile(p, body, 0o755)) }
	out := []string{write(path), "unlink=" + status(os.Remove(path))}
	if out[1] == "unlink=ok" {
		out = append(out, write(path))
	}
	out = append(out, "add="+status(os.WriteFile(filepath.Join(root, "bin", "evil"), body, 0o755)))
	dev, ro := mountOf(root)
	if !ro {
		return strings.Join(append(out, "remount=skipped,device=skipped"), " ")
	}
	if msg := output("mount", "-o", "remount,rw", root); msg != "" {
		out = append(out, "remount="+msg)
	} else {
		out = append(out, "remount=ok,"+write(path))
	}
	f, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err == nil {
		_, err = f.WriteAt(make([]byte, 4096), 1024) // the ext4 superblock
		f.Close()
	}
	out = append(out, "device="+status(err))
	if msg := output("mount", "-o", "rw", dev, "/mnt"); msg != "" {
		out = append(out, "mount="+msg)
	} else {
		out = append(out, "mount=ok,"+write(filepath.Join("/mnt", "bin", filepath.Base(path))))
	}
	return strings.Join(out, " ")
}

// status is "ok" or the error in a word.
func status(err error) string {
	if err != nil {
		return short(err)
	}
	return "ok"
}

// mountOf is the device behind the mount at point, and whether it is read-only.
func mountOf(point string) (string, bool) {
	b, _ := os.ReadFile("/proc/self/mountinfo")
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if i := slices.Index(f, "-"); len(f) > 5 && f[4] == point && i > 0 && i+2 < len(f) {
			return f[i+2], strings.HasPrefix(f[5]+",", "ro,")
		}
	}
	return "", false
}

// output is what the command printed, in one word: a version, or an error.
func output(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil && len(bytes.TrimSpace(b)) == 0 {
		return short(err)
	}
	return strings.Join(strings.Fields(string(b)), "_")
}

// treeSum hashes every regular file and symlink below root, by relative
// path, mode and content, into twelve hex characters.
func treeSum(root string) string {
	h := sha256.New()
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		fmt.Fprintf(h, "%s %o ", strings.TrimPrefix(p, root), d.Type())
		if t, err := os.Readlink(p); err == nil {
			io.WriteString(h, t)
		} else if f, err := os.Open(p); err == nil {
			io.Copy(h, f)
			f.Close()
		}
		return nil
	})
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}
