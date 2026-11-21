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

// TestFailSparesALayerThisStartDidNotInstall (I12, B10; finding C43 of S-1016d): fresh names the image this start installed, not a provider, so a layer the operator
// chose since is not one of its own. A session kept silent by guest root while the operator runs `workcell update --rollback` must not, by a forged first frame, undo it.
func TestFailSparesALayerThisStartDidNotInstall(t *testing.T) {
	p, dir := must(provider.All())[0], t.TempDir()
	layers := filepath.Join(dir, "layers", p.Name)
	old, fresh := "1.0.1-aa.ext4", "1.0.3-bb.ext4" // fresh: what this start's apply installed over old
	_, _, _, _, _ = os.MkdirAll(layers, 0o700), os.WriteFile(filepath.Join(layers, old), nil, 0o600), os.WriteFile(filepath.Join(layers, fresh), nil, 0o600), writeMarker(layers, "current", fresh), writeMarker(layers, "previous", old)
	rows := []pins.Pin{{Name: p.Install.Pin, Release: pins.Release{Version: "1.0.3"}}} // the operator, in another terminal, runs workcell update --rollback:
	must(installer{dir: dir, rows: rows}.update(context.Background(), p, nil, "", true))
	installer{dir: dir, fresh: []string{fresh}}.fail(p.Binary, io.Discard) // the session's forged first frame
	if cur, failed := marker(layers, "current"), marker(layers, "failed"); cur != old || failed != "" {
		t.Errorf("after the operator's --rollback and one forged first frame: current %q, failed %q; want the operator's %q and nothing set aside", cur, failed, old)
	}
}
