// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The provider layer row (I7, B8). The host installs the agents in layers
// from an upstream the judge serves on its own loopback (SPEC T8), each in
// the shape its real upstream uses, as `workcell update` does; root in the
// guest does what it can to the layer the session runs claude from
// (hijack), and a second session must run the versions the host installed
// from a layer whose every file is as it was, the image on the host too.
// In between, the upstream serves claude as bytes whose digest is not the
// row's, which the host must refuse and keep the layer it had (B8).
// hijacked is what the guest's own agent, or the mismatched bytes, print.
var layers = map[string]string{"claude": "9.9.9", "codex": "8.8.8"}

const layerAgent, hijacked = "claude", "6.6.6"

// shaped is the artifact an agent's upstream serves for a binary that
// prints version, and the path it serves it at: claude a bare executable,
// codex a gzip tar whose only entry, at the root, is named by the target
// triple. The binary is a shell script as far as the row cares.
func shaped(agent, version string) (string, []byte) {
	body := []byte("#!/bin/sh\necho " + version + "\n")
	if agent != "codex" {
		return "/" + version + "/linux-x64/" + agent, body
	}
	name := "codex-" + map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH] + "-unknown-linux-musl"
	var art bytes.Buffer
	gz := gzip.NewWriter(&art)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	gz.Close()
	return "/" + name + ".tar.gz", art.Bytes()
}

// install has the host install agent at version from src, which serves the
// shaped artifact the row's digest names, or served when that is not nil.
func install(ctx context.Context, s Session, src *upstream, agent, version string, served []byte) (string, error) {
	path, art := shaped(agent, version)
	if served == nil {
		served = art
	}
	src.set(path, whole(served))
	return s.Install(ctx, sandbox.Layer{Agent: agent, Version: version, URL: src.url + path, Artifact: art})
}

// layerJudge installs every agent of layers, has the host refuse a digest
// mismatch, and compares what two sessions see.
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
	var image string
	for _, agent := range slices.Sorted(maps.Keys(layers)) {
		img, err := install(ctx, s, src, agent, layers[agent], nil)
		if err != nil {
			return false, "", err
		}
		if agent == layerAgent {
			image = img
		}
	}
	before, err := fileSum(image)
	if err != nil {
		return false, "", err
	}
	_, refused := install(ctx, s, src, layerAgent, "7.7.7", []byte("#!/bin/sh\necho "+hijacked+"\n"))
	r, err := s.Run("attack", hijacked)
	if err != nil {
		return false, "", err
	}
	two, err := s.Another()
	var r2 Result
	if err == nil {
		r2, err = two.Run("check", hijacked)
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
	case refused == nil:
		return false, "the host installed " + layerAgent + " from bytes whose digest is not the row's; " + both, nil
	case missing(one) != "":
		return false, "the first session did not run the " + missing(one) + " the host installed; " + both, nil
	case before != after:
		return false, "the layer image on the host changed under the session; " + both, nil
	case missing(other) != "":
		return false, "the second session did not run the " + missing(other) + " the host installed; " + both, nil
	case other["hash"] != one["hash"]:
		return false, "the second session saw a layer the first changed; " + both, nil
	}
	return true, both, nil
}

// missing names the first agent of layers whose version a session, by its
// detail, did not print; "" when it printed them all.
func missing(got map[string]string) string {
	for _, agent := range slices.Sorted(maps.Keys(layers)) {
		if got[agent] != layers[agent] {
			return agent
		}
	}
	return ""
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

// layerProbe finds each agent of layers on PATH and runs `<agent>
// --version`; hashes every file of claude's layer (the parent of the
// binary's directory); and, as "attack", tries as root to make claude print
// the version given, then says what it prints afterwards. args: verb, version.
func layerProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want attack|check and version"}
	}
	var detail []string
	for _, agent := range slices.Sorted(maps.Keys(layers)) {
		path, err := exec.LookPath(agent)
		if err != nil {
			detail = append(detail, agent+"=none")
			continue
		}
		detail = append(detail, agent+"="+output(path, "--version"))
		if agent == layerAgent {
			root := filepath.Dir(filepath.Dir(path))
			detail = append(detail, "hash="+treeSum(root))
			if args[0] == "attack" {
				detail = append(detail, hijack(path, root, []byte("#!/bin/sh\necho "+args[1]+"\n")), "runs="+output(path, "--version"))
			}
		}
	}
	return Result{Status: "tried", Detail: strings.Join(detail, " ")}
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
