// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Command guest is PID 1 of the spike's microVM (the only file of its initramfs).
// It reads its token and a host loopback address from the shared disk or
// directory, dials the address, talks to the host over vsock, writes the echo
// back to the share and powers the VM off. It never returns: a PID 1 that exits
// is a kernel panic, and a panic loop would spin the VMM.
//
// "guest probe <addr> [sleep s]" is the Apple container mode: it mounts nothing,
// uses no vsock, prints the hello line to stdout, sleeps and exits 7.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	exitCode  = 7
	echoAt    = 4096 // where the echo goes on the block device
	echoBytes = 2048
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "probe" {
		fmt.Println(hello("probe", os.Args[2]))
		if len(os.Args) > 3 {
			s, _ := strconv.Atoi(os.Args[3])
			time.Sleep(time.Duration(s) * time.Second)
		}
		os.Exit(exitCode)
	}
	setup()
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintln(os.Stderr, "guest: panic:", r)
			}
		}()
		if err := run(); err != nil {
			fmt.Fprintln(os.Stderr, "guest:", err)
		}
	}()
	unix.Sync()
	// Neither VMM carries an exit code. Firecracker exits 0 on a keyboard-controller
	// reset (reboot=k). Cloud Hypervisor answers a reset by rebooting in place, so its
	// exit path is the ACPI power-off.
	how := unix.LINUX_REBOOT_CMD_POWER_OFF
	if os.Getenv("wcexit") == "reboot" {
		how = unix.LINUX_REBOOT_CMD_RESTART
	}
	for {
		fmt.Fprintln(os.Stderr, "guest: reboot:", unix.Reboot(how))
		time.Sleep(time.Second)
	}
}

func setup() {
	for _, d := range []string{"/dev", "/proc", "/sys", "/work"} {
		_ = os.MkdirAll(d, 0o755)
	}
	mount("devtmpfs", "/dev", "devtmpfs")
	if fd, err := unix.Open("/dev/console", unix.O_RDWR, 0); err == nil {
		_ = unix.Dup3(fd, 1, 0)
		_ = unix.Dup3(fd, 2, 0)
	}
	mount("proc", "/proc", "proc")
	mount("sysfs", "/sys", "sysfs")
}

func mount(src, dir, fs string) {
	if err := unix.Mount(src, dir, fs, 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
		fmt.Fprintln(os.Stderr, "guest: mount", dir, err)
	}
}

func run() error {
	var token, probe string
	var put func(echo string) error
	var err error
	switch share := os.Getenv("wcshare"); share {
	case "blk":
		token, probe, put, err = blkShare()
	case "fs":
		token, probe, put, err = fsShare()
	default:
		err = fmt.Errorf("wcshare=%q", share)
	}
	if err != nil {
		return err
	}
	conn, err := vsockConnect()
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := fmt.Fprintln(conn, hello(token, probe)); err != nil {
		return err
	}
	echo, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	return put(echo)
}

// hello dials the host loopback probe and reports what the guest sees. The
// default gateway is read from the routing table, never dialled.
func hello(token, probe string) string {
	loopback := "err"
	if c, err := net.DialTimeout("tcp", probe, 2*time.Second); err == nil {
		loopback = "ok"
		_ = c.Close()
	}
	ifaces := "none"
	if ents, err := os.ReadDir("/sys/class/net"); err == nil && len(ents) > 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		ifaces = strings.Join(names, ",")
	}
	cmdline, _ := os.ReadFile("/proc/cmdline")
	leak := "no"
	if os.Getenv("WC_CANARY") != "" || bytes.Contains(cmdline, []byte("WC_CANARY")) {
		leak = "yes"
	}
	return fmt.Sprintf("hello %s loopback=%s ifaces=%s gateway=%s env_leak=%s exit=%d cmdline=%s",
		token, loopback, ifaces, gateway(), leak, exitCode, url.QueryEscape(strings.TrimSpace(string(cmdline))))
}

// gateway is the IPv4 default route's gateway from /proc/net/route, or "none".
func gateway() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "none"
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		g, err := strconv.ParseUint(f[2], 16, 32)
		if err == nil {
			return net.IPv4(byte(g), byte(g>>8), byte(g>>16), byte(g>>24)).String()
		}
	}
	return "none"
}

// vsockConnect dials the host (CID 2) port 5000. The device may still be
// probing when the guest starts, so it retries for 5 s.
func vsockConnect() (*os.File, error) {
	var err error
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		var fd int
		if fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
			continue
		}
		if err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: 5000}); err == nil {
			return os.NewFile(uintptr(fd), "vsock"), nil
		}
		_ = unix.Close(fd)
	}
	return nil, fmt.Errorf("vsock connect: %w", err)
}

// blkShare reads "<token> <probe>" from the first 512 bytes of /dev/vda and
// writes the echo at offset 4096.
func blkShare() (token, probe string, put func(string) error, err error) {
	var f *os.File
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if f, err = os.OpenFile("/dev/vda", os.O_RDWR, 0); err == nil {
			break
		}
	}
	if err != nil {
		return "", "", nil, err
	}
	buf := make([]byte, 512)
	if _, err = f.ReadAt(buf, 0); err != nil {
		return "", "", nil, fmt.Errorf("read /dev/vda: %w", err)
	}
	text, _, _ := bytes.Cut(buf, []byte{0})
	fields := strings.Fields(string(text))
	if len(fields) != 2 {
		return "", "", nil, fmt.Errorf("share header %q", text)
	}
	return fields[0], fields[1], func(echo string) error {
		if len(echo) > echoBytes {
			return fmt.Errorf("echo is %d bytes, room for %d", len(echo), echoBytes)
		}
		out := make([]byte, echoBytes)
		copy(out, echo)
		_, err := f.WriteAt(out, echoAt)
		if err == nil {
			err = f.Sync()
		}
		return err
	}, nil
}

// fsShare mounts virtio-fs tag "work" and uses the same three files as the libkrun spike.
func fsShare() (token, probe string, put func(string) error, err error) {
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if err = unix.Mount("work", "/work", "virtiofs", 0, ""); err == nil {
			break
		}
	}
	if err != nil {
		return "", "", nil, fmt.Errorf("mount work: %w", err)
	}
	t, err := os.ReadFile("/work/from-host.txt")
	if err != nil {
		return "", "", nil, err
	}
	p, err := os.ReadFile("/work/probe.txt")
	if err != nil {
		return "", "", nil, err
	}
	return strings.TrimSpace(string(t)), strings.TrimSpace(string(p)), func(echo string) error {
		return os.WriteFile("/work/from-guest.txt", []byte(echo), 0o644)
	}, nil
}
