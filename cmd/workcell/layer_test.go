// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

func TestLayerArgsAndPath(t *testing.T) {
	const base = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	tests := []struct {
		name   string
		layers []vmm.Layer
		first  rune
		args   string
		path   string
	}{
		{"none", nil, 'c', "", "PATH=" + base},
		{"one, after the workspace", []vmm.Layer{{Name: "claude", Image: "/l/c.ext4"}}, 'c', " workcell.layer=claude:/dev/vdc", "PATH=/opt/claude/bin:" + base},
		{"two, mount mode", []vmm.Layer{{Name: "codex"}, {Name: "claude"}}, 'b', " workcell.layer=codex:/dev/vdb workcell.layer=claude:/dev/vdc", "PATH=/opt/codex/bin:/opt/claude/bin:" + base},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := layerArgs(tc.layers, tc.first); got != tc.args {
				t.Errorf("layerArgs = %q, want %q", got, tc.args)
			}
			if got := pathEnv(tc.layers); got != tc.path {
				t.Errorf("pathEnv = %q, want %q", got, tc.path)
			}
		})
	}
}

func TestFindLayers(t *testing.T) {
	tests := []struct {
		name, marker, image string // the current marker of claude, and the image file to make
		want                []vmm.Layer
		err                 string
	}{
		{"no marker", "", "", nil, ""},
		{"a layer", "9.9.9-0123456789abcdef.ext4\n", "9.9.9-0123456789abcdef.ext4", []vmm.Layer{{Name: "claude", Image: "layers/claude/9.9.9-0123456789abcdef.ext4"}}, ""},
		{"a marker naming no image", "9.9.9-0123456789abcdef.ext4\n", "", nil, "the claude layer 9.9.9-0123456789abcdef.ext4 is missing; run workcell update claude"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sub := filepath.Join(dir, "layers", "claude")
			os.MkdirAll(sub, 0o700)
			for _, f := range []struct{ name, body string }{{"current", tc.marker}, {tc.image, "ext4"}} {
				if f.name != "" && f.body != "" {
					os.WriteFile(filepath.Join(sub, f.name), []byte(f.body), 0o600)
				}
			}
			for i := range tc.want {
				tc.want[i].Image = filepath.Join(dir, tc.want[i].Image)
			}
			got, err := findLayers(dir)
			if (err == nil) != (tc.err == "") || err != nil && err.Error() != tc.err || !slices.Equal(got, tc.want) {
				t.Errorf("findLayers = %v, %v; want %v, %q", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestCacheArgsAndEnv(t *testing.T) {
	tests := []struct {
		name   string
		caches []vmm.Cache
		args   string
		env    []string
	}{
		{"none", nil, "", nil},
		{"go, read-only", []vmm.Cache{{Name: "go"}}, " workcell.cache=go:/dev/vdd:ro", []string{"GOMODCACHE=/cache/go/mod", "GOCACHE=/cache/go/build"}},
		{"npm and another, writable", []vmm.Cache{{Name: "npm", Writable: true}, {Name: "pip"}}, " workcell.cache=npm:/dev/vdd:rw workcell.cache=pip:/dev/vde:ro", []string{"npm_config_cache=/cache/npm"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheArgs(tc.caches, 'd'); got != tc.args {
				t.Errorf("cacheArgs = %q, want %q", got, tc.args)
			}
			if got := cacheEnv(tc.caches); !slices.Equal(got, tc.env) {
				t.Errorf("cacheEnv = %q, want %q", got, tc.env)
			}
		})
	}
}
