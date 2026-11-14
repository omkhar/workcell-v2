// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A KVM host reports a guest's vCPU time in guest and guest_nice and again in user and nice; the judge must count it once, or a capped guest looks like
// it spent twice its CPU.
func TestBusyTicksCountsGuestTimeOnce(t *testing.T) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	got, err := busyTicks("cpu 1000 10 200 5000 30 4 6 7 900 8")
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(1000 + 10 + 200 + 4 + 6 + 7); got != want {
		t.Fatalf("busyTicks = %d, want %d", got, want)
	}
	if _, err := busyTicks("cpu 1 2 3"); err == nil {
		t.Fatal("a short cpu line parsed")
	}
}

// A mount-mode disk flood whose run failed, or whose probe never reported the flood as tried, must not pass on a zero loss: the error is the row's,
// and any other report fails the row with the guest's own words in it.
func TestMountDiskJudgeNeverPassesWithoutATriedReport(t *testing.T) {
	ws := t.TempDir()
	want := errors.New("payload exited 137: killed")
	s := Session{Workspace: ws, Guest: "/workspace", Run: func(...string) (Result, error) { return Result{}, want }}
	if pass, _, err := mountDiskJudge(context.Background(), s); pass || !errors.Is(err, want) {
		t.Fatalf("a failed run judged pass=%v err=%v, want the run's error", pass, err)
	}
	s.Run = func(...string) (Result, error) { return Result{Status: "created", Detail: "export only"}, nil }
	pass, detail, err := mountDiskJudge(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if pass || !strings.Contains(detail, "created: export only") {
		t.Fatalf("a report that is not tried judged pass=%v %q", pass, detail)
	}
}
