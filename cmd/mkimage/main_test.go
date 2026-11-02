// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/rootfs"
)

const hex64 = "f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4"

func pin(mod func(*pins.Pin)) pins.Pin {
	p := pins.Pin{Source: pins.OCI, Locator: "https://r.example:5000/v2/library/debian"}
	p.Artifacts = map[string]pins.Artifact{"amd64": {SHA256: hex64}, "arm64": {SHA256: hex64}}
	if mod != nil {
		mod(&p)
	}
	return p
}

func TestImageFromPin(t *testing.T) {
	loc := func(s string) func(*pins.Pin) { return func(p *pins.Pin) { p.Locator = s } }
	sha := func(s string) func(*pins.Pin) {
		return func(p *pins.Pin) { p.Artifacts["amd64"] = pins.Artifact{SHA256: s} }
	}
	tests := []struct {
		name string
		pin  pins.Pin
		arch string
		want rootfs.Image
		bad  bool
	}{
		{"amd64", pin(nil), "amd64", rootfs.Image{Registry: "https://r.example:5000", Repository: "library/debian", Digest: "sha256:" + hex64, OS: "linux", Arch: "amd64"}, false},
		{"arm64", pin(nil), "arm64", rootfs.Image{Registry: "https://r.example:5000", Repository: "library/debian", Digest: "sha256:" + hex64, OS: "linux", Arch: "arm64"}, false},
		{"source", pin(func(p *pins.Pin) { p.Source = pins.NPM }), "amd64", rootfs.Image{}, true},
		{"http", pin(loc("http://r.example/v2/a")), "amd64", rootfs.Image{}, true},
		{"no host", pin(loc("https:///v2/a")), "amd64", rootfs.Image{}, true},
		{"bad port", pin(loc("https://r.example:abc/v2/a")), "amd64", rootfs.Image{}, true},
		{"no v2", pin(loc("https://r.example/a")), "amd64", rootfs.Image{}, true},
		{"empty repository", pin(loc("https://r.example/v2/")), "amd64", rootfs.Image{}, true},
		{"query", pin(loc("https://r.example/v2/a?x=1")), "amd64", rootfs.Image{}, true},
		{"missing arch", pin(nil), "riscv64", rootfs.Image{}, true},
		{"uppercase", pin(sha(strings.ToUpper(hex64))), "amd64", rootfs.Image{}, true},
		{"short", pin(sha(hex64[1:])), "amd64", rootfs.Image{}, true},
		{"prefixed", pin(sha("sha256:" + hex64)), "amd64", rootfs.Image{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := imageFromPin(tt.pin, tt.arch)
			if (err != nil) != tt.bad || got != tt.want {
				t.Errorf("got %+v, %v", got, err)
			}
		})
	}
}

func TestPinFile(t *testing.T) {
	b, err := os.ReadFile("../../pins/debian.json")
	if err != nil {
		t.Fatal(err)
	}
	var p pins.Pin
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		img, err := imageFromPin(p, arch)
		if err != nil || img.Registry != "https://mirror.gcr.io" || img.Repository != "library/debian" {
			t.Errorf("%s: %+v, %v", arch, img, err)
		}
	}
}
