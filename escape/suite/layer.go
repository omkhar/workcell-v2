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

// The provider layer row (I7, B8). The host installs the agents in layers from
// an upstream the judge serves (T8), each in its real upstream's shape; root
// in the guest does what it can to claude's layer (hijack), and a second
// session must run the versions the host installed from a layer unchanged.
// In between, bytes whose digest is not the row's must be refused (B8).
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
	for _, agent := range slices.Sorted(maps.Keys(layers)) {
		if _, err = install(ctx, s, src, agent, layers[agent], nil); err != nil {
			return false, "", err
		}
	}
	_, refused := install(ctx, s, src, layerAgent, "7.7.7", []byte("#!/bin/sh\necho "+hijacked+"\n"))
	r, err := s.Run("attack", hijacked)
	if err != nil {
		return false, "", err
	}
	two, err := s.Another(nil)
	var r2 Result
	if err == nil {
		r2, err = two.Run("check", hijacked)
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
	case missing(other) != "":
		return false, "the second session did not run the " + missing(other) + " the host installed; " + both, nil
	case other["hash"] != one["hash"]:
		return false, "the second session saw a layer the first changed; " + both, nil
	}
	return true, both, nil
}

// missing names the first agent of layers whose version got lacks, "" for none.
func missing(got map[string]string) string {
	for _, agent := range slices.Sorted(maps.Keys(layers)) {
		if got[agent] != layers[agent] {
			return agent
		}
	}
	return ""
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

// layerProbe runs `<agent> --version` for each agent of layers on PATH,
// hashes every file of claude's layer (the parent of the binary's directory)
// and, as "attack", tries as root to make claude print the version given,
// then says what it prints. Versions first: a detail is cut at maxDetail.
func layerProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want attack|check and version"}
	}
	var detail []string
	for _, agent := range slices.Sorted(maps.Keys(layers)) {
		if path, err := exec.LookPath(agent); err != nil {
			detail = append(detail, agent+"=none")
		} else {
			detail = append(detail, agent+"="+output(path, "--version"))
		}
	}
	path, err := exec.LookPath(layerAgent)
	if err != nil {
		return Result{Status: "missing", Detail: strings.Join(detail, " ")}
	}
	root := filepath.Dir(filepath.Dir(path))
	detail = append(detail, "hash="+treeSum(root))
	if args[0] == "attack" {
		detail = append(detail, hijack(path, root, []byte("#!/bin/sh\necho "+args[1]+"\n")), "runs="+output(path, "--version"))
	}
	return Result{Status: "tried", Detail: strings.Join(detail, " ")}
}

// hijack tries what root has to change the layer at root, whose binary is
// path: a write, an unlink and a fresh file, and a new file beside it. The
// judge decides on the second session's view, whatever these say.
func hijack(path, root string, body []byte) string {
	write := func(p string) string { return "write=" + status(os.WriteFile(p, body, 0o755)) }
	out := []string{write(path), "unlink=" + status(os.Remove(path))}
	if out[1] == "unlink=ok" {
		out = append(out, write(path))
	}
	return strings.Join(append(out, "add="+status(os.WriteFile(filepath.Join(root, "bin", "evil"), body, 0o755))), " ")
}

// status is "ok" or the error in a word.
func status(err error) string {
	if err != nil {
		return short(err)
	}
	return "ok"
}

// output is what the command printed, in one word: a version, or how it failed.
func output(name string, args ...string) string {
	how, out := ran(3*time.Second, nil, name, args...)
	if out == "" && how != "0" {
		return how
	}
	return out
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
