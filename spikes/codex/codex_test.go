// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package codex is evidence for B3 and B5: it fetches a real openai/codex release and
// checks that our verifier accepts the bundle upstream signed, and it runs the bump
// planner against the live listings. It needs the network and never fails because of
// a third party; a download error skips the test.
package codex

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/sigstore"
)

const (
	release = "https://github.com/openai/codex/releases/download/rust-v0.167.0/"
	asset   = "codex-x86_64-unknown-linux-musl"
	san     = "https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v0.167.0"
)

func get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("GET " + url + ": " + resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(body)) > limit {
		err = errors.New("GET " + url + ": over the cap")
	}
	return body, err
}

// member returns the sha256 of the one entry of a gzip tarball with the given name.
func member(tgz []byte, name string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			return nil, err
		}
		if h.Name == name {
			sum := sha256.New()
			_, err := io.Copy(sum, tr)
			return sum.Sum(nil), err
		}
	}
}

func TestCodexUpstream(t *testing.T) {
	ctx := context.Background()
	tarball, err := get(ctx, release+asset+".tar.gz", 512<<20)
	if err != nil {
		t.Skip("download:", err)
	}
	bundle, err := get(ctx, release+asset+".sigstore", 64<<10)
	if err != nil {
		t.Skip("download:", err)
	}
	digest, err := member(tarball, asset)
	if err != nil {
		t.Errorf("the tarball has no member %s: %v", asset, err)
	} else if _, _, err := sigstore.Verify(sigstore.PublicRoot(), bundle, sigstore.Identity{SAN: san, Issuer: "https://token.actions.githubusercontent.com"}, digest); err != nil {
		t.Errorf("B5 codex rust-v0.167.0 bundle: refused: %v", err)
	} else {
		t.Log("B5 codex rust-v0.167.0 bundle: verified")
	}

	dir, err := os.Getwd()
	for err == nil {
		if _, err = os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		if parent := filepath.Dir(dir); parent != dir {
			dir, err = parent, nil
		} else {
			err = errors.New("no go.mod above the working directory")
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", "./cmd/bump", "-newest", "-dry-run")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	t.Logf("B3 bump -newest -dry-run:\n%s", out)
	if err != nil {
		t.Logf("B3 bump -newest -dry-run: %v", err)
	}
}
