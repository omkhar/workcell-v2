// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"testing"
)

// The forged first frame is exactly the candidate's bytes: version 1, type
// Exit, a length of 5, then the text tag and "nope".
func TestForgedFirstFrame(t *testing.T) {
	want := []byte{0x01, 0x07, 0x00, 0x00, 0x00, 0x05, 0x02, 0x6e, 0x6f, 0x70, 0x65}
	if got := frame(typeExit, textTag([]byte(noExecText))); !bytes.Equal(got, want) {
		t.Errorf("frame % x, want % x", got, want)
	}
}

// The probe refuses what it cannot run, and the check says what it sees.
func TestRollbackProbeArgs(t *testing.T) {
	for _, args := range [][]string{nil, {"forge"}, {"other"}} {
		if r := rollbackProbe(args); r.Status != "error" {
			t.Errorf("%q: %+v, want an error", args, r)
		}
	}
	if r := rollbackProbe([]string{"check"}); r.Status != "present" && r.Status != "missing" {
		t.Errorf("check: %+v", r)
	}
}
