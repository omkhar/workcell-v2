// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/omkhar/workcell/v2/internal/provider"
	"github.com/omkhar/workcell/v2/internal/vmm"
)

// findLayers is the current layer of every provider that has one under dir, in provider
// order: the image that layers/<agent>/current names (update). A provider with no marker
// has no layer, and a session boots as it did without one. A marker naming an image that
// is not there is a refusal, before anything boots.
func findLayers(dir string) ([]vmm.Layer, error) {
	all, err := provider.All()
	if err != nil {
		return nil, err
	}
	var ls []vmm.Layer
	for _, p := range all {
		sub := filepath.Join(dir, "layers", p.Name)
		name := marker(sub, "current")
		if name == "" {
			continue
		}
		image := filepath.Join(sub, name)
		if _, err := os.Stat(image); err != nil {
			return nil, fmt.Errorf("the %s layer %s is missing; run workcell update %s", p.Name, name, p.Name)
		}
		ls = append(ls, vmm.Layer{Name: p.Name, Image: image})
	}
	return ls, nil
}

// layerArgs is the init's workcell.layer=<agent>:<device> for each layer, in the order the
// backend attaches the drives, the first of them at the drive letter first.
func layerArgs(layers []vmm.Layer, first rune) string {
	var s strings.Builder
	for i, l := range layers {
		fmt.Fprintf(&s, " workcell.layer=%s:/dev/vd%c", l.Name, first+rune(i))
	}
	return s.String()
}

// pathEnv is the command's PATH: the bin of each layer, in order, before the image's own.
func pathEnv(layers []vmm.Layer) string {
	s := "PATH="
	for _, l := range layers {
		s += "/opt/" + l.Name + "/bin:"
	}
	return s + "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}
