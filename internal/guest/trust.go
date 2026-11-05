// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package guest

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// The session's CA in the guest. The host terminates TLS for every allowed name with a leaf
// of a CA made for the session (I6), so a client in the guest validates only if it trusts
// that CA. The init writes the certificate where clients look and the host names it in the
// variables they read: a convenience for clients, never an enforcement (A1). The key never
// leaves the host (I5).
const (
	TrustDir = "/etc/ssl/certs" // where Debian keeps its trust store
	MaxCA    = 16 << 10         // bytes of CA PEM an Exec may carry
)

const (
	bundleFile  = "ca-certificates.crt" // Debian's bundle, where clients look by default
	caFile      = "workcell-ca.pem"     // the session CA alone
	jksFile     = "workcell-ca.jks"     // the bundle as a Java keystore
	jksPassword = "changeit"            // Java's own default; the variables name none, so Java skips the digest
)

// TrustEnv is the environment that names the trust stores under dir, for curl, Python
// (requests), Node, Java and Go.
func TrustEnv(dir string) []string {
	bundle := filepath.Join(dir, bundleFile)
	return []string{
		"SSL_CERT_FILE=" + bundle, "CURL_CA_BUNDLE=" + bundle, "REQUESTS_CA_BUNDLE=" + bundle,
		"NODE_EXTRA_CA_CERTS=" + filepath.Join(dir, caFile),
		"JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=" + filepath.Join(dir, jksFile) + " -Djavax.net.ssl.trustStoreType=JKS",
	}
}

// WriteTrust puts caPEM in the trust stores under dir: appended to the bundle, which is
// created when there is none, alone in the PEM file, and in a Java keystore with everything
// the bundle holds. The same CA twice is appended once.
func WriteTrust(dir string, caPEM []byte, now time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	bundle := filepath.Join(dir, bundleFile)
	have, err := os.ReadFile(bundle)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !bytes.Contains(have, caPEM) {
		if len(have) > 0 && have[len(have)-1] != '\n' {
			have = append(have, '\n')
		}
		have = append(have, caPEM...)
		if err := os.WriteFile(bundle, have, 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, caFile), caPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, jksFile), jks(certificates(have), now), 0o644)
}

// certificates is the DER of every CERTIFICATE block in a PEM bundle.
func certificates(bundle []byte) (certs [][]byte) {
	for {
		var b *pem.Block
		if b, bundle = pem.Decode(bundle); b == nil {
			return certs
		}
		if b.Type == "CERTIFICATE" {
			certs = append(certs, b.Bytes)
		}
	}
}

// jks encodes certs, DER each, as a Java keystore of trusted certificate entries, the format
// every JDK reads: the magic, version 2, the entries, then SHA-1 over the password in
// UTF-16BE, the bytes "Mighty Aphrodite" and the entries.
func jks(certs [][]byte, now time.Time) []byte {
	b := binary.BigEndian.AppendUint32(nil, 0xFEEDFEED)
	b = binary.BigEndian.AppendUint32(b, 2)
	b = binary.BigEndian.AppendUint32(b, uint32(len(certs)))
	for i, der := range certs {
		b = binary.BigEndian.AppendUint32(b, 2) // a trusted certificate entry
		b = javaUTF(b, "workcell-"+strconv.Itoa(i))
		b = binary.BigEndian.AppendUint64(b, uint64(now.UnixMilli()))
		b = javaUTF(b, "X.509")
		b = binary.BigEndian.AppendUint32(b, uint32(len(der)))
		b = append(b, der...)
	}
	h := sha1.New()
	for _, c := range jksPassword {
		h.Write([]byte{byte(c >> 8), byte(c)})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(b)
	return h.Sum(b)
}

// javaUTF appends s as Java's DataOutput.writeUTF does: two bytes of length, then the
// bytes, which for ASCII are the string's own.
func javaUTF(b []byte, s string) []byte {
	return append(binary.BigEndian.AppendUint16(b, uint16(len(s))), s...)
}
