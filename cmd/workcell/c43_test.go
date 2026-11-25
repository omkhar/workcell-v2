// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/provider"
)

// TestFailSparesALayerThisStartDidNotInstall (I12, B10; finding C43 of S-1016d): fresh pairs the image this start installed with the one it replaced, not a provider's name, so a layer the operator chose by `workcell update --rollback` while guest root kept the session silent is not this start's, even once a later start's apply has moved on and the rollback made this start's image current again; a forged first frame does not undo the operator.
func TestFailSparesALayerThisStartDidNotInstall(t *testing.T) {
	p, dir := must(provider.All())[0], t.TempDir()
	layers := filepath.Join(dir, "layers", p.Name)
	old, fresh, next := "1.0.1-aa.ext4", "1.0.3-bb.ext4", "1.0.5-cc.ext4" // fresh: what this start's apply installed over old; next: what a later start's apply installs
	in := installer{dir: dir, rows: []pins.Pin{{Name: p.Install.Pin, Release: pins.Release{Version: "1.0.5", Artifacts: map[string]pins.Artifact{"amd64": {URL: "https://127.0.0.1:1/unreachable", SHA256: "cc"}, "arm64": {URL: "https://127.0.0.1:1/unreachable", SHA256: "cc"}}}}}}
	_, _, _, _, _, _ = os.MkdirAll(layers, 0o700), os.WriteFile(filepath.Join(layers, old), nil, 0o600), os.WriteFile(filepath.Join(layers, fresh), nil, 0o600), writeMarker(layers, "current", fresh), writeMarker(layers, "previous", old), must(in.update(context.Background(), p, nil, "", true)) // then the operator, in another terminal, runs workcell update --rollback, and the session forges its first frame:
	installer{dir: dir, fresh: []string{fresh + "\n" + old}}.fail(p.Binary, io.Discard)
	if cur, failed := marker(layers, "current"), marker(layers, "failed"); cur != old || failed != "" {
		t.Errorf("after the operator's --rollback and one forged first frame: current %q, failed %q; want the operator's %q and nothing set aside", cur, failed, old)
	}
	_, _, _, _ = writeMarker(layers, "current", fresh), writeMarker(layers, "previous", old), os.WriteFile(filepath.Join(layers, next), nil, 0o600), writeMarker(layers, "failed", next) // back to before that rollback, with next on disk and set aside by an earlier start, so that a second start's apply installs it over fresh without a fetch while this session is silent:
	_, _ = must(in.update(context.Background(), p, nil, "1.0.5", false)), must(in.update(context.Background(), p, nil, "", true))
	installer{dir: dir, fresh: []string{fresh + "\n" + old}}.fail(p.Binary, io.Discard) // the operator rolled that back (current fresh, previous next) and this session forges its first frame: current is fresh again, but previous is not what fresh replaced
	if cur, prev, failed := marker(layers, "current"), marker(layers, "previous"), marker(layers, "failed"); cur != fresh || prev != next || failed != "" {
		t.Errorf("after a second start's install, the operator's --rollback and one forged first frame: current %q previous %q failed %q; want the operator's %q, %q and nothing set aside", cur, prev, failed, fresh, next)
	}
}
