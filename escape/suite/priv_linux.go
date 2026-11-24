// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"cmp"
	"errors"
	"fmt"
	"github.com/omkhar/workcell/v2/escape/sandbox"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

// A canary or a resolver on a port below 1024 needs root on the test host, which the suite does not have on a hosted runner, where sudo answers without a password. So the payload binds it as root and hands the descriptor over (sandbox.RootBind): the judge stays what it is, and root ran one bind. The same payload, entered as root into a session's own network namespaces, binds the judge's canaries there.

// Bind is the payload as root on the test host: it binds network/addr, sends the descriptor to the judge waiting at the unix socket path, and exits 0. Any failure is one line on stderr and exit 1.
func Bind(network, addr, path string) int {
	f, err := bindFile(network, addr)
	var c net.Conn
	if err == nil {
		if c, err = net.Dial("unix", path); err == nil {
			_, _, err = c.(*net.UnixConn).WriteMsgUnix([]byte{0}, syscall.UnixRights(int(f.Fd())), nil)
			c.Close()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bind:", err)
		return 1
	}
	return 0
}

// bindFile binds network/addr and returns the socket as a file.
func bindFile(network, addr string) (*os.File, error) {
	if strings.HasPrefix(network, "udp") {
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			return nil, err
		}
		defer pc.Close()
		return pc.(*net.UDPConn).File()
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.(*net.TCPListener).File()
}

// Hold is the payload as the holder of a session's own network, started in a fresh network namespace (`unshare -n`) as root, where the product then runs (/proc/<pid>/ns/net). It gives that namespace an Internet that is not the product's own host: a second namespace, held by a child of its own, joined to the first by a veth link. The product's side, wc0, holds sandbox.IsolatedNet and reaches sandbox.CanaryAddr by a route in the main table via sandbox.Neighbour, a gateway on the link; the far side, wc1, holds Neighbour, a real neighbour that answers for itself, and CanaryAddr on its loopback device behind it, where the judge's canaries listen (sandbox.RootBind, entered there). With onLink wc0 holds the host's address alone, as a /32, and the prefix around it is on-link through a route in the main table alone, as a cloud NIC's or a DHCP classless route lays it out. It dials the judge at path, says both pids, and stays until the judge hangs up; the far holder goes with it.
func Hold(path string, onLink bool) int {
	ip, ipnet, err := net.ParseCIDR(sandbox.IsolatedNet)
	gw, canary := net.ParseIP(sandbox.Neighbour).To4(), net.ParseIP(sandbox.CanaryAddr).To4()
	self, _ := os.Executable()
	far := exec.Command(self, "helper", "far") // the far holder: nothing but a process in its namespace, killed when this one goes
	far.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	if err == nil {
		err = far.Start()
	}
	var wc0 *net.Interface
	if err == nil {
		defer func() { far.Process.Kill(); far.Wait() }()
		if err = cmp.Or(veth("wc0", "wc1", far.Process.Pid), linkUp("lo")); err == nil {
			wc0, err = net.InterfaceByName("wc0")
		}
	}
	width, _ := ipnet.Mask.Size()
	bits := width
	if onLink {
		bits = 32
	}
	if err == nil {
		err = held("wc0", ip.To4(), bits)
	}
	if err == nil && onLink {
		err = route(wc0.Index, ipnet.IP.To4(), width, syscall.RT_TABLE_MAIN, syscall.RT_SCOPE_LINK, syscall.RTN_UNICAST, nil)
	}
	if err == nil {
		err = route(wc0.Index, canary, 32, syscall.RT_TABLE_MAIN, syscall.RT_SCOPE_UNIVERSE, syscall.RTN_UNICAST, gw)
	}
	if err == nil {
		err = inNetns(far.Process.Pid, func() error { return cmp.Or(held("lo", canary, 32), held("wc1", gw, width)) })
	}
	var c net.Conn
	if err == nil {
		c, err = net.Dial("unix", path)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "netns:", err)
		return 1
	}
	defer c.Close()
	fmt.Fprintf(c, "pid %d far %d\n", os.Getpid(), far.Process.Pid)
	io.Copy(io.Discard, c)
	return 0
}

// Routed is the payload's check of a session's network, entered as root into the product's namespace (sandbox.isolate): it asks the kernel for the route to sandbox.CanaryAddr and to sandbox.Neighbour, and refuses a local one for either, since that would make the address the product's own host's, or one to CanaryAddr without a gateway, since the canary must stand behind a neighbour as the Internet does. It exits 0 when the layout holds; any failure is one line on stderr and exit 1.
func Routed() int {
	for _, a := range []string{sandbox.CanaryAddr, sandbox.Neighbour} {
		table, typ, gw, err := routed(net.ParseIP(a).To4())
		if err == nil && (table == syscall.RT_TABLE_LOCAL || typ == syscall.RTN_LOCAL) {
			err = errors.New("a local route, which makes it an address of the product's own host")
		}
		if err == nil && a == sandbox.CanaryAddr && gw == nil {
			err = errors.New("no gateway, so the canary is not behind a neighbour")
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "routed: the route to %s: %v\n", a, err)
			return 1
		}
	}
	return 0
}

var linuxRows = []Test{{ID: "I4", Name: "rebind-on-link-neighbour-forward", Probe: rebindProbe, Host: rebindJudge(rebind{canary: "neighbour"}), Want: rebindingOnLink}} // linuxRows are the rows only a Linux host runs, since they need that on-link layout, which the Mac's static lo0 setup cannot hold beside the ordinary one (sandbox.Config.OnLink, refused there): the same neighbour as rebind-host-network-forward, with the host's own address held as a /32 and the prefix around it on-link through a route alone, as a cloud NIC or a DHCP classless route lays it out; no interface prefix holds the neighbour, and it is the host's LAN still (I4).
// held brings the named interface up, holding ip4/bits.
func held(name string, ip4 net.IP, bits int) error {
	ifc, err := net.InterfaceByName(name)
	if err == nil {
		err = linkUp(name)
	}
	if err == nil {
		err = addrRequest(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, ifc.Index, ip4, bits, syscall.RT_SCOPE_UNIVERSE)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// inNetns runs f on this thread moved into the network namespace of the process pid, and moves it back: no other goroutine runs there meanwhile, since the thread is locked, and none is left there, which matters when the thread is the main one, whose namespace /proc/<pid>/ns/net names and which Go wedges rather than discards.
func inNetns(pid int, f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	here, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer here.Close()
	ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err == nil {
		defer ns.Close()
		err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET)
	}
	if err == nil {
		defer unix.Setns(int(here.Fd()), unix.CLONE_NEWNET)
		err = f()
	}
	return err
}

// linkUp brings the named interface up, as `ip link set <name> up` does.
func linkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
