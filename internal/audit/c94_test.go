// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// C94 (I9): after a Record of session_end has returned nil, nothing more is recorded: a Note or a
// Record returns an error and adds no line, and the log's last line is the session_end record. A log
// with records after its end is what `workcell verify` calls incomplete; audit.Verify returns nil.

package audit

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// c94Round ends a session while writers Note refused connections. It returns how many records
// follow session_end, whether Verify accepts the log as ended, and a line describing both.
func c94Round(t *testing.T, writers int) (after int, ended bool, got string) {
	t.Helper()
	key, _ := LoadKey(t.TempDir())
	dir := filepath.Join(t.TempDir(), "ws-c94")
	os.Mkdir(dir, 0o700)
	l, _ := Create(dir, key, time.Now)
	l.Record(Record{Event: SessionStart})
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for l.Note(Record{Event: Connect, Port: 443, Result: "no_sni"}) == nil {
			}
		})
	}
	time.Sleep(3 * time.Millisecond)
	l.Record(Record{Event: SessionEnd, Result: "exit 0"})
	l.Close()
	wg.Wait()
	if l.Note(Record{Event: Connect, Port: 443, Result: "no_sni"}) == nil {
		t.Error("a Note after Close returned nil")
	}
	b, _ := os.ReadFile(filepath.Join(dir, LogName))
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	after = len(lines) - 1 - strings.Count(string(b[:max(strings.Index(string(b), `"event":"`+SessionEnd+`"`), 0)]), "\n")
	last, err := Verify(dir, key.Public().(ed25519.PublicKey))
	got = fmt.Sprintf("last line %s; %d records after session_end; Verify = %v, last.Event = %q", lines[len(lines)-1], after, err, last.Event)
	return after, err == nil && last.Event == SessionEnd, got
}

func TestC94NothingIsRecordedAfterTheSessionEnds(t *testing.T) {
	t.Run("control: no writer", func(t *testing.T) {
		if after, ended, got := c94Round(t, 0); after != 0 || !ended {
			t.Error(got)
		}
	})
	t.Run("finding: 256 writers racing the end", func(t *testing.T) {
		bad, got := 0, ""
		for range 10 {
			if after, _, g := c94Round(t, 256); after > 0 {
				bad, got = bad+1, g
			}
		}
		if bad > 0 {
			t.Errorf("%d of 10 rounds recorded after session_end; %s", bad, got)
		}
	})
}
