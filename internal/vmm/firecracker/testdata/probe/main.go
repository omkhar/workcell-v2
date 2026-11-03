// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Command probe is what TestInit asks workcell-init to run inside the guest. Its first
// argument says what it does; what the test checks goes to stdout, one line each.
package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	mode, n := "", 0
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	if len(os.Args) > 2 {
		n, _ = strconv.Atoi(os.Args[2])
	}
	switch mode {
	case "pty": // who runs it, whether stdin is a terminal and how big; again after a resize; then exit n
		_, tty := unix.IoctlGetTermios(0, unix.TCGETS)
		fmt.Printf("ppid=%d tty=%t %s\n", os.Getppid(), tty == nil, size())
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, unix.SIGWINCH)
		<-ch
		fmt.Println(size())
		os.Exit(n)
	case "pipes": // stdin back on stdout, a word on stderr
		_, _ = io.Copy(os.Stdout, os.Stdin)
		fmt.Fprintln(os.Stderr, "err")
	case "sleep": // until a signal ends it
		fmt.Println("sleeping")
		time.Sleep(time.Minute)
	case "orphans": // n children, half gone before this ends and half after, none waited for
		for i := range n {
			arg := []string{"exit", "linger"}[i%2]
			if _, err := os.StartProcess(os.Args[0], []string{os.Args[0], arg}, &os.ProcAttr{}); err != nil {
				fmt.Fprintln(os.Stderr, "probe:", err)
				os.Exit(1)
			}
		}
	case "linger":
		time.Sleep(100 * time.Millisecond)
	case "zombies": // processes in state Z, once the orphans are gone or had 2 s to be reaped
		var z, procs, linger int
		for end := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			z, procs, linger = scan()
			if z == 0 && linger == 0 || time.Now().After(end) {
				break
			}
		}
		fmt.Printf("zombies=%d procs=%d linger=%d\n", z, procs, linger)
	case "exit":
	default:
		fmt.Fprintln(os.Stderr, "probe: unknown mode", mode)
		os.Exit(2)
	}
}

func size() string {
	ws, err := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ)
	if err != nil {
		return "winsize=" + err.Error()
	}
	return fmt.Sprintf("rows=%d cols=%d", ws.Row, ws.Col)
}

// scan counts the processes in /proc, those in state Z and the linger children still alive.
func scan() (zombies, procs, linger int) {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		procs++
		if _, state, _ := strings.Cut(string(b), ") "); strings.HasPrefix(state, "Z") {
			zombies++
		} else if c, _ := os.ReadFile("/proc/" + e.Name() + "/cmdline"); strings.HasSuffix(string(c), "linger\x00") {
			linger++
		}
	}
	return zombies, procs, linger
}
