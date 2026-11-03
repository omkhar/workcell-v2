// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import "testing"

// A KVM host reports a guest's vCPU time in guest and guest_nice and again in
// user and nice; the judge must count it once, or a capped guest looks like
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
