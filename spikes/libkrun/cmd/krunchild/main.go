// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Command krunchild boots one libkrun microVM through purego and never returns
// on success: krun_start_enter takes the process, and the VMM exits with the
// guest's exit code. The spike test runs it on a KVM host only.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ebitengine/purego"
)

var (
	createCtx            func() int32
	setLogLevel          func(level uint32) int32
	setVMConfig          func(ctx uint32, vcpus uint8, mib uint32) int32
	setRoot              func(ctx uint32, path string) int32
	addVirtiofs          func(ctx uint32, tag, path string) int32
	setExec              func(ctx uint32, path string, argv, envp **byte) int32
	addVsockPort         func(ctx uint32, port uint32, path string) int32
	disableImplicitVsock func(ctx uint32) int32
	addVsock             func(ctx uint32, tsiFeatures uint32) int32
	disableImplicitInit  func(ctx uint32) int32
	setConsoleOutput     func(ctx uint32, path string) int32
	startEnter           func(ctx uint32) int32
)

func main() {
	lib := flag.String("lib", "", "directory holding libkrun.so and libkrunfw.so.5")
	root := flag.String("root", "", "guest root directory")
	work := flag.String("work", "", "directory shared as virtio-fs tag work")
	sock := flag.String("sock", "", "host unix socket for the guest's vsock port")
	port := flag.Uint("port", 5000, "guest vsock port")
	console := flag.String("console", "", "file for the guest console")
	cpus := flag.Uint("cpus", 2, "vCPUs")
	mem := flag.Uint("mem", 1024, "memory in MiB")
	hijack := flag.Bool("hijack", true, "keep the implicit vsock with TSI hijacking")
	pid1 := flag.Bool("pid1", false, "disable the built-in init; the guest is /init.krun")
	probe := flag.Bool("probe", false, "stop after creating and configuring a context")
	flag.Parse()
	runtime.LockOSThread()

	if _, err := purego.Dlopen(filepath.Join(*lib, "libkrunfw.so.5"), purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
		fail("dlopen libkrunfw: %v", err)
	}
	h, err := purego.Dlopen(filepath.Join(*lib, "libkrun.so"), purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		fail("dlopen libkrun: %v", err)
	}
	for name, fn := range map[string]any{
		"krun_create_ctx": &createCtx, "krun_set_log_level": &setLogLevel, "krun_set_vm_config": &setVMConfig,
		"krun_set_root": &setRoot, "krun_add_virtiofs": &addVirtiofs, "krun_set_exec": &setExec,
		"krun_add_vsock_port": &addVsockPort, "krun_disable_implicit_vsock": &disableImplicitVsock,
		"krun_add_vsock": &addVsock, "krun_disable_implicit_init": &disableImplicitInit,
		"krun_set_console_output": &setConsoleOutput, "krun_start_enter": &startEnter,
	} {
		purego.RegisterLibFunc(fn, h, name)
	}

	check("krun_set_log_level", setLogLevel(1)) // errors only
	rc := createCtx()
	check("krun_create_ctx", rc)
	ctx := uint32(rc)
	check("krun_set_vm_config", setVMConfig(ctx, uint8(*cpus), uint32(*mem)))
	if *probe {
		fmt.Printf("ctx=%d\n", ctx)
		return
	}
	if *pid1 {
		check("krun_disable_implicit_init", disableImplicitInit(ctx))
	}
	check("krun_set_root", setRoot(ctx, *root))
	check("krun_add_virtiofs", addVirtiofs(ctx, "work", *work))
	if !*hijack {
		check("krun_disable_implicit_vsock", disableImplicitVsock(ctx))
		check("krun_add_vsock", addVsock(ctx, 0))
	}
	check("krun_add_vsock_port", addVsockPort(ctx, uint32(*port), *sock))
	check("krun_set_console_output", setConsoleOutput(ctx, *console))
	// A NULL envp would copy this process's whole environment onto the guest
	// kernel command line, so both arrays are explicit and empty.
	argv, envp := []*byte{nil}, []*byte{nil}
	check("krun_set_exec", setExec(ctx, "/guest", &argv[0], &envp[0]))
	runtime.KeepAlive(argv)
	runtime.KeepAlive(envp)

	fmt.Printf("enter_unix_ns=%d\n", time.Now().UnixNano())
	rc = startEnter(ctx)
	fmt.Printf("start_enter=%d\n", rc)
	os.Exit(3)
}

func check(name string, rc int32) {
	if rc < 0 {
		fail("%s=%d", name, rc)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "krunchild: "+format+"\n", args...)
	os.Exit(2)
}
