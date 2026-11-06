// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestBuild(t *testing.T) {
	f := newFixture(t,
		tarOf(dir("etc/"), reg("etc/old", "x"), reg("bin", "y")),
		tarOf(reg("etc/new", "z"), reg("etc/.wh.old", ""), sym("etc/link", "new")))
	var err error
	var out [2]bytes.Buffer
	var res [2]Result
	for i := range out {
		if res[i], err = Build(context.Background(), f.client, f.img, &out[i]); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(out[0].Bytes())
	if res[0] != res[1] || res[0].Digest != "sha256:"+hex.EncodeToString(sum[:]) || res[0].Size != int64(out[0].Len()) || !bytes.Equal(out[0].Bytes(), out[1].Bytes()) {
		t.Errorf("builds differ or disagree with the bytes: %+v %+v", res[0], res[1])
	}
	if b := out[0].Bytes(); len(b) < 1100 || binary.LittleEndian.Uint16(b[1024+56:]) != 0xEF53 {
		t.Error("the image has no ext4 superblock")
	}
}

func TestBuildPullFailure(t *testing.T) {
	f := newFixture(t, tarOf(reg("a", "b")))
	f.img.Digest = dg([]byte("nothing"))
	var out bytes.Buffer
	if _, err := Build(context.Background(), f.client, f.img, &out); err == nil || out.Len() != 0 {
		t.Errorf("err %v, %d bytes written", err, out.Len())
	}
}

func TestLimitWriter(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name   string
		ctx    context.Context
		limit  int64
		writes []string
		err    error
		kept   string
	}{
		{"under", context.Background(), 8, []string{"abc", "de"}, nil, "abcde"},
		{"exact", context.Background(), 5, []string{"abc", "de"}, nil, "abcde"},
		{"over", context.Background(), 4, []string{"abc", "de"}, ErrTooLarge, "abc"},
		{"cancelled", cancelled, 8, []string{"abc"}, context.Canceled, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			lw := &limitWriter{ctx: tt.ctx, w: &out, h: sha256.New(), limit: tt.limit}
			var err error
			for _, s := range tt.writes {
				if _, err = lw.Write([]byte(s)); err != nil {
					break
				}
			}
			// bare hides the cause of a cancelled context, so only the over-limit error is typed.
			if (tt.err == ErrTooLarge && !errors.Is(err, ErrTooLarge)) || (tt.err == nil) != (err == nil) {
				t.Errorf("err %v, want %v", err, tt.err)
			}
			sum := sha256.Sum256([]byte(tt.kept))
			if out.String() != tt.kept || lw.n != int64(len(tt.kept)) || !bytes.Equal(lw.h.Sum(nil), sum[:]) {
				t.Errorf("kept %q (n %d), want %q", out.String(), lw.n, tt.kept)
			}
		})
	}
}
