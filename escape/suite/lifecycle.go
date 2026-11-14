// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// SPEC I9, the record of a session's end. The operator pipes a run into a reader that stops early, `workcell run -- <cmd> | head -1`, and the
// command in the guest goes on writing. The host process shows the guest's output on the operator's stdout; once that reader is gone, the next line
// must not take the host process with it, since its last duties come after the command: the session's end in the record, and its files and sockets
// released (I7). The run must end as the command did, exit 0, and its record must hold its start and its end, as every run's does
// (offlineJudge counts on the same two).

// chatterPause is how long the command waits after its first line, so that the host has shown it and the operator's reader has gone before the next.
const chatterPause = time.Second

// chatterProbe writes one line, waits, writes more, and ends as any command does.
func chatterProbe([]string) Result {
	fmt.Println("chatter 1")
	time.Sleep(chatterPause)
	for i := 2; i <= 4; i++ {
		fmt.Println("chatter", i)
		time.Sleep(chatterPause / 10)
	}
	return Result{Status: "ended", Detail: "wrote 4 lines and ended"}
}

// chatterJudge runs the command once with the operator's reader gone after its first line (Want.Head), and expects the run to end as the command did
// and to add its start and its end to the record.
func chatterJudge(ctx context.Context, s Session) (bool, string, error) {
	_, before, err := s.Audit(ctx)
	if err != nil {
		return false, "", err
	}
	out, err := s.Exec(ctx)
	if err != nil {
		return false, "", err
	}
	if !bytes.HasPrefix(out.Stdout, []byte("chatter 1\n")) {
		return false, "", fmt.Errorf("the operator's reader got %q before it went, not the command's first line", firstLine(out.Stdout))
	}
	_, after, err := s.Audit(ctx)
	if err != nil {
		return false, "", err
	}
	added := len(after) - len(before)
	say := fmt.Sprintf("with the operator's reader gone after the first line, the run ended with exit %d (%s) and added %d records", out.Exit, firstLine(out.Stderr), added)
	switch {
	case out.Exit != 0:
		return false, say + "; the command itself ended with exit 0", nil
	case added < 2:
		return false, say + "; a run leaves at least its start and its end", nil
	}
	return true, say + ": the command's own exit, and its end recorded", nil
}
