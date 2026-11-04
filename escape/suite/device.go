// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// deviceJudge binds a host block device (a loop device) to an image holding
// the token, tells the guest its numbers, and fails if the guest reads the
// token through a device node it makes. The attacker knows the host's device
// numbers; the invariant must hold anyway.
func deviceJudge(ctx context.Context, s Session) (bool, string, error) {
	token := newToken()
	img := filepath.Join(filepath.Dir(s.Workspace), "disk.img")
	if err := os.WriteFile(img, append([]byte(token+"\n"), make([]byte, 1<<20)...), 0o644); err != nil {
		return false, "", err
	}
	dev, err := losetup("--find", "--show", img)
	if err != nil {
		return false, "", err
	}
	defer losetup("--detach", dev)
	fi, err := os.Stat(dev)
	if err != nil {
		return false, "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, "", errors.New("no device numbers for " + dev)
	}
	maj, min := unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))
	r, err := s.Run(strconv.FormatUint(uint64(maj), 10), strconv.FormatUint(uint64(min), 10))
	if err != nil {
		return false, "", err
	}
	if strings.Contains(r.Detail, token) {
		return false, fmt.Sprintf("the guest read the host's disk %s (%d:%d) through a device node it made (guest says %s: %s)", dev, maj, min, r.Status, r.Detail), nil
	}
	return true, "guest says " + r.Status + ": " + r.Detail, nil
}

// losetup runs losetup(8), through sudo when the runner is not root, as a
// hosted runner grants without a password, and returns what it printed.
func losetup(args ...string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("a host loop device is Linux only")
	}
	cmd := exec.Command("losetup", args...)
	if os.Geteuid() != 0 {
		cmd = exec.Command("sudo", append([]string{"-n", "losetup"}, args...)...)
	}
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", fmt.Errorf("losetup %s: %v: %s", args[0], err, strings.TrimSpace(string(exit.Stderr)))
		}
		return "", fmt.Errorf("losetup %s: %w", args[0], err)
	}
	return strings.TrimSpace(string(out)), nil
}
