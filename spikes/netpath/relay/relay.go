// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package relay is what the netpath spike's guest and host share: the 20-byte
// header that opens every relayed stream, the two-byte frame of a relayed
// datagram, the port list on the kernel command line, the key=value reply
// lines, the median, and the splice of two streams.
package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const (
	Control   = 5000 // the vsock port of the host's control connection
	Port      = 5001 // the vsock port the guest dials once per relayed stream
	HeaderLen = 20   // version, proto, port (big-endian), 16-byte address
	Version   = 1
	TCP       = 6
	UDP       = 17
)

// Header is the original destination of one relayed stream.
type Header struct {
	Proto byte
	Dst   netip.AddrPort
}

// Encode is the header on the wire; an IPv4 address goes as IPv4-mapped IPv6.
func (h Header) Encode() []byte {
	b := make([]byte, HeaderLen)
	b[0], b[1] = Version, h.Proto
	binary.BigEndian.PutUint16(b[2:], h.Dst.Port())
	a := h.Dst.Addr().As16()
	copy(b[4:], a[:])
	return b
}

// Decode reads a header. The bytes come from the guest.
func Decode(b []byte) (Header, error) {
	switch {
	case len(b) != HeaderLen:
		return Header{}, fmt.Errorf("header is %d bytes, want %d", len(b), HeaderLen)
	case b[0] != Version:
		return Header{}, fmt.Errorf("header version %d", b[0])
	case b[1] != TCP && b[1] != UDP:
		return Header{}, fmt.Errorf("header proto %d", b[1])
	}
	addr := netip.AddrFrom16([16]byte(b[4:])).Unmap()
	return Header{Proto: b[1], Dst: netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[2:]))}, nil
}

// Frame prefixes a datagram with its length, as DNS over TCP does.
func Frame(b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

// ReadFrame reads one framed datagram.
func ReadFrame(r io.Reader) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(n[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

// Ports is the list in "workcell.ports=443,80" on a kernel command line.
func Ports(cmdline string) ([]uint16, error) {
	for _, f := range strings.Fields(cmdline) {
		v, ok := strings.CutPrefix(f, "workcell.ports=")
		if !ok {
			continue
		}
		var ps []uint16
		for _, s := range strings.Split(v, ",") {
			n, err := strconv.ParseUint(s, 10, 16)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("workcell.ports: bad port %q", s)
			}
			ps = append(ps, uint16(n))
		}
		return ps, nil
	}
	return nil, errors.New("no workcell.ports= on the kernel command line")
}

// Config is how a kernel config (the text of /proc/config.gz) sets sym:
// its value (y, m, a number), n when "is not set", or absent.
func Config(text, sym string) string {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(l, "CONFIG_"+sym+"="); ok {
			return v
		}
		if l == "# CONFIG_"+sym+" is not set" {
			return "n"
		}
	}
	return "absent"
}

// Pair is one key=value of a reply line; the value is made one printable word.
func Pair(key string, v any) string { return key + "=" + Clean(fmt.Sprint(v)) }

// Err is the pair of a measurement that failed.
func Err(key string, err error) string { return Pair(key, "err:"+err.Error()) }

// Clean replaces every byte that is not printable ASCII or is a blank with '_'
// and cuts the result to 160 bytes.
func Clean(s string) string {
	b := []byte(s[:min(len(s), 160)])
	for i, c := range b {
		if c <= ' ' || c > '~' {
			b[i] = '_'
		}
	}
	return string(b)
}

// Join is the reply line of the pairs.
func Join(pairs []string) string { return strings.Join(pairs, " ") + "\n" }

// Parse reads a reply line; a word without '=' is ignored.
func Parse(line string) map[string]string {
	kv := map[string]string{}
	for _, f := range strings.Fields(line) {
		if k, v, ok := strings.Cut(f, "="); ok && k != "" {
			kv[k] = v
		}
	}
	return kv
}

// Stats is the median (the mean of the two middle values for an even count),
// the minimum and the maximum; all -1 for no values.
func Stats(v []int64) (p50, lo, hi int64) {
	if len(v) == 0 {
		return -1, -1, -1
	}
	s := slices.Sorted(slices.Values(v))
	n := len(s)
	if n%2 == 1 {
		return s[n/2], s[0], s[n-1]
	}
	return (s[n/2-1] + s[n/2]) / 2, s[0], s[n-1]
}

// Splice copies both ways until both directions end. The end of one direction
// is passed on as a half-close where the writer has CloseWrite, else as a close.
func Splice(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	one := func(dst, src io.ReadWriteCloser) {
		_, err := io.Copy(dst, src)
		if h, ok := dst.(interface{ CloseWrite() error }); ok && err == nil && h.CloseWrite() == nil {
			return
		}
		_ = dst.Close()
		_ = src.Close()
	}
	wg.Go(func() { one(a, b) })
	wg.Go(func() { one(b, a) })
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
