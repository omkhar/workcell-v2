// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64 && cgo

// Command vzchild boots one Linux microVM through Virtualization.framework
// (github.com/Code-Hex/vz/v3) and does the spike's vsock exchange with it. It
// prints key=value lines on stdout for the test: start_unix_ns before
// vm.Start, first_unix_ns on the first vsock byte, line= (what the guest sent),
// eof_unix_ns at vsock EOF and exit_path= once the VM has stopped. It needs
// the com.apple.security.virtualization entitlement; without it, it prints
// validate_err= or start_err= and exits 3. With -noecho it never answers the
// guest, so the VM stays up until the process is killed (the SIGKILL boot).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Code-Hex/vz/v3"
)

const (
	port      = 5000
	bootLimit = 60 * time.Second
	stopLimit = 10 * time.Second
)

func main() {
	kernel := flag.String("kernel", "", "arm64 Image")
	initrd := flag.String("initrd", "", "initramfs")
	cmdline := flag.String("cmdline", "", "kernel command line")
	img := flag.String("img", "", "raw disk image, attached as virtio-blk")
	share := flag.String("share", "", "directory shared as virtio-fs tag work")
	console := flag.String("console", "", "file for the guest console (hvc0)")
	cpus := flag.Uint("cpus", 2, "vCPUs")
	mem := flag.Uint64("mem", 1024, "memory in MiB")
	noecho := flag.Bool("noecho", false, "read the guest's line but never answer it")
	flag.Parse()
	vm, err := build(*kernel, *initrd, *cmdline, *img, *share, *console, *cpus, *mem)
	if err != nil {
		fmt.Printf("validate_err=%q\n", err.Error())
		os.Exit(3)
	}
	os.Exit(run(vm, *noecho))
}

func build(kernel, initrd, cmdline, img, share, console string, cpus uint, mem uint64) (*vz.VirtualMachine, error) {
	boot, err := vz.NewLinuxBootLoader(kernel, vz.WithCommandLine(cmdline), vz.WithInitrd(initrd))
	if err != nil {
		return nil, err
	}
	cfg, err := vz.NewVirtualMachineConfiguration(boot, cpus, mem<<20)
	if err != nil {
		return nil, err
	}
	out, err := vz.NewFileSerialPortAttachment(console, false)
	if err != nil {
		return nil, err
	}
	serial, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(out)
	if err != nil {
		return nil, err
	}
	cfg.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{serial})
	sock, err := vz.NewVirtioSocketDeviceConfiguration()
	if err != nil {
		return nil, err
	}
	cfg.SetSocketDevicesVirtualMachineConfiguration([]vz.SocketDeviceConfiguration{sock})
	if img != "" {
		disk, err := vz.NewDiskImageStorageDeviceAttachment(img, false)
		if err != nil {
			return nil, err
		}
		blk, err := vz.NewVirtioBlockDeviceConfiguration(disk)
		if err != nil {
			return nil, err
		}
		cfg.SetStorageDevicesVirtualMachineConfiguration([]vz.StorageDeviceConfiguration{blk})
	}
	if share != "" {
		fs, err := vz.NewVirtioFileSystemDeviceConfiguration("work")
		if err != nil {
			return nil, err
		}
		dir, err := vz.NewSharedDirectory(share, false)
		if err != nil {
			return nil, err
		}
		single, err := vz.NewSingleDirectoryShare(dir)
		if err != nil {
			return nil, err
		}
		fs.SetDirectoryShare(single)
		cfg.SetDirectorySharingDevicesVirtualMachineConfiguration([]vz.DirectorySharingDeviceConfiguration{fs})
	}
	if ok, err := cfg.Validate(); !ok || err != nil {
		return nil, fmt.Errorf("validate: %v", err)
	}
	return vz.NewVirtualMachine(cfg)
}

func run(vm *vz.VirtualMachine, noecho bool) int {
	stopped := make(chan struct{})
	go func() {
		for s := range vm.StateChangedNotify() {
			fmt.Printf("state=%s\n", strings.TrimPrefix(s.String(), "VirtualMachineState"))
			if s == vz.VirtualMachineStateStopped || s == vz.VirtualMachineStateError {
				close(stopped)
				return
			}
		}
	}()
	// The listener can be set before Start; if the device list is empty until
	// then, listen after it (the guest retries its connect for 5 s).
	var ln *vz.VirtioSocketListener
	listen := func() (err error) {
		if devs := vm.SocketDevices(); len(devs) > 0 {
			ln, err = devs[0].Listen(port)
		}
		return err
	}
	if err := listen(); err != nil {
		fmt.Printf("listen_err=%q\n", err.Error())
		return 3
	}
	listenAt := "before_start"
	fmt.Printf("start_unix_ns=%d\n", time.Now().UnixNano())
	if err := vm.Start(); err != nil {
		fmt.Printf("start_err=%q\n", err.Error())
		return 3
	}
	if ln == nil {
		listenAt = "after_start"
		if err := listen(); err != nil || ln == nil {
			fmt.Printf("listen_err=%q\n", fmt.Sprint(err))
			return 3
		}
	}
	fmt.Printf("listen=%s\n", listenAt)
	got := make(chan error, 1)
	go func() { got <- exchange(ln, noecho) }()
	report := func(err error) {
		if err != nil {
			fmt.Printf("exchange_err=%q\n", err.Error())
		}
	}
	select {
	case err := <-got:
		report(err)
	case <-stopped: // the guest powers off right after it closes, so EOF may come second
		select {
		case err := <-got:
			report(err)
		case <-time.After(2 * time.Second):
			fmt.Println("exchange_err=\"VM stopped first\"")
		}
	case <-time.After(bootLimit):
		fmt.Println("exchange_err=\"timeout\"")
	}
	select {
	case <-stopped:
		fmt.Println("exit_path=poweroff")
	case <-time.After(stopLimit):
		fmt.Printf("exit_path=hang stop_err=%q\n", fmt.Sprint(vm.Stop()))
	}
	return 0
}

// exchange accepts the guest's connection, echoes its first line and waits for EOF.
func exchange(ln *vz.VirtioSocketListener, noecho bool) error {
	var c net.Conn
	var err error
	if c, err = ln.Accept(); err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(bootLimit))
	br := bufio.NewReader(c)
	if _, err = br.Peek(1); err != nil {
		return err
	}
	fmt.Printf("first_unix_ns=%d\n", time.Now().UnixNano())
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Printf("line=%s", line)
	if noecho {
		select {}
	}
	if _, err = io.WriteString(c, line); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, br)
	fmt.Printf("eof_unix_ns=%d\n", time.Now().UnixNano())
	return err
}
