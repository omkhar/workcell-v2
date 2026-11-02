// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64

// Command krunchild boots one libkrun microVM on macOS through purego, without
// cgo, from a raw arm64 kernel and an initramfs (libkrun's external_kernel
// example). It never returns on success: krun_start_enter takes the process.
// It prints enter_unix_ns= just before that call, call_err=<call>=<rc> and
// exit 2 if a call fails, and start_enter=<rc> and exit 3 if it returns.
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
	setLogLevel          func(level uint32) int32
	createCtx            func() int32
	setVMConfig          func(ctx uint32, vcpus uint8, mib uint32) int32
	addDisk              func(ctx uint32, id, path string, readOnly bool) int32
	disableImplicitVsock func(ctx uint32) int32
	addVsock             func(ctx uint32, tsiFeatures uint32) int32
	addVsockPort         func(ctx uint32, port uint32, path string) int32
	setConsoleOutput     func(ctx uint32, path string) int32
	setKernel            func(ctx uint32, path string, format uint32, initrd, cmdline string) int32
	startEnter           func(ctx uint32) int32
)

// The VMM's event loop must run on the main thread.
func init() { runtime.LockOSThread() }

func main() {
	lib := flag.String("lib", "", "directory holding libkrun.dylib and its three dependencies")
	kernel := flag.String("kernel", "", "raw arm64 Image")
	initrd := flag.String("initrd", "", "initramfs")
	cmdline := flag.String("cmdline", "", "kernel command line")
	img := flag.String("img", "", "raw disk image, attached as virtio-blk")
	sock := flag.String("sock", "", "host unix socket for the guest's vsock port 5000")
	console := flag.String("console", "", "file for the guest console")
	cpus := flag.Uint("cpus", 2, "vCPUs")
	mem := flag.Uint("mem", 1024, "memory in MiB")
	flag.Parse()

	h, err := purego.Dlopen(filepath.Join(*lib, "libkrun.dylib"), purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		fmt.Printf("call_err=%q\n", "dlopen: "+err.Error())
		os.Exit(2)
	}
	for name, fn := range map[string]any{
		"krun_set_log_level": &setLogLevel, "krun_create_ctx": &createCtx, "krun_set_vm_config": &setVMConfig,
		"krun_add_disk": &addDisk, "krun_add_vsock_port": &addVsockPort, "krun_set_console_output": &setConsoleOutput,
		"krun_set_kernel": &setKernel, "krun_start_enter": &startEnter,
	} {
		purego.RegisterLibFunc(fn, h, name)
	}
	vsock := "implicit"
	if _, err := purego.Dlsym(h, "krun_disable_implicit_vsock"); err == nil {
		if _, err := purego.Dlsym(h, "krun_add_vsock"); err == nil {
			purego.RegisterLibFunc(&disableImplicitVsock, h, "krun_disable_implicit_vsock")
			purego.RegisterLibFunc(&addVsock, h, "krun_add_vsock")
			vsock = "explicit"
		}
	}

	check("krun_set_log_level", setLogLevel(1)) // errors only
	rc := createCtx()
	check("krun_create_ctx", rc)
	ctx := uint32(rc)
	check("krun_set_vm_config", setVMConfig(ctx, uint8(*cpus), uint32(*mem)))
	check("krun_add_disk", addDisk(ctx, "share", *img, false))
	if vsock == "explicit" { // no TSI: vsock is only the port map
		check("krun_disable_implicit_vsock", disableImplicitVsock(ctx))
		check("krun_add_vsock", addVsock(ctx, 0))
	}
	fmt.Printf("vsock=%s\n", vsock)
	check("krun_add_vsock_port", addVsockPort(ctx, 5000, *sock))
	check("krun_set_console_output", setConsoleOutput(ctx, *console))
	check("krun_set_kernel", setKernel(ctx, *kernel, 0 /* RAW */, *initrd, *cmdline))
	fmt.Printf("enter_unix_ns=%d\n", time.Now().UnixNano())
	fmt.Printf("start_enter=%d\n", startEnter(ctx))
	os.Exit(3)
}

func check(name string, rc int32) {
	if rc < 0 {
		fmt.Printf("call_err=%s=%d\n", name, rc)
		os.Exit(2)
	}
}
