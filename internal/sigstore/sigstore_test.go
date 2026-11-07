// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sigstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

const (
	identity = "https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v0.0.1"
	issuer   = "https://token.actions.githubusercontent.com"
	v03      = "application/vnd.dev.sigstore.bundle.v0.3+json"
	v01      = "application/vnd.dev.sigstore.bundle+json;version=0.1"
	v02      = "application/vnd.dev.sigstore.bundle+json;version=0.2"
)

var (
	signed       = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) // leaf NotBefore
	oidOldIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	artifact     = sha256.Sum256([]byte("artifact"))
	other        = sha256.Sum256([]byte("other"))
	statement    = []byte(`{"_type":"ab>>>"}`) // base64 holds a "+" and padding
)

func p256(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t testing.TB, tmpl, parent *x509.Certificate, key, parentKey crypto.Signer) *x509.Certificate {
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func caTmpl(serial int64) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprint("ca", serial)},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func name(tag int, s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: []byte(s)}
}

func ext(id asn1.ObjectIdentifier, v []byte) pkix.Extension { return pkix.Extension{Id: id, Value: v} }

func der(s, params string) []byte {
	v, _ := asn1.MarshalWithParams(s, params)
	return v
}

// leafTmpl is a 10-minute Fulcio-shaped leaf with the given SAN names and issuer extensions.
func leafTmpl(names []asn1.RawValue, exts ...pkix.Extension) *x509.Certificate {
	san, _ := asn1.Marshal(names)
	return &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: signed, NotAfter: signed.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: append([]pkix.Extension{ext(oidSAN, san)}, exts...)}
}

func sign(t testing.TB, k crypto.Signer, digest []byte) []byte {
	sig, err := k.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func spki(t testing.TB, k crypto.Signer) []byte {
	b, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fixture struct {
	rootCert, inter   *x509.Certificate
	interKey, rekor   *ecdsa.PrivateKey
	rekorID           []byte
	root              *Root
	tooEarly, tooLate *Root // CA window misses the leaf's NotBefore
	logEnded, ctOnly  *Root // Rekor key window ends before signing; Rekor key only under ctlogs
}

func newFixture(t testing.TB) *fixture {
	f := &fixture{rekor: p256(t), interKey: p256(t)}
	rootKey := p256(t)
	f.rootCert = issue(t, caTmpl(1), nil, rootKey, nil)
	f.inter = issue(t, caTmpl(2), f.rootCert, f.interKey, rootKey)
	id := sha256.Sum256(spki(t, f.rekor))
	f.rekorID = id[:]
	f.root = f.parse(t, "2000-01-01T00:00:00Z", "", "", "tlogs")
	f.tooEarly = f.parse(t, signed.Add(time.Second).Format(time.RFC3339), "", "", "tlogs")
	f.tooLate = f.parse(t, "2000-01-01T00:00:00Z", signed.Add(-time.Second).Format(time.RFC3339), "", "tlogs")
	f.logEnded = f.parse(t, "2000-01-01T00:00:00Z", "", signed.Format(time.RFC3339), "tlogs")
	f.ctOnly = f.parse(t, "2000-01-01T00:00:00Z", "", "", "ctlogs")
	return f
}

// parse builds a trusted root JSON with the fixture's CA and Rekor key and parses it.
func (f *fixture) parse(t testing.TB, caStart, caEnd, logEnd, logsField string) *Root {
	win := func(start, end string) map[string]any {
		w := map[string]any{"start": start}
		if end != "" {
			w["end"] = end
		}
		return w
	}
	rekor := map[string]any{"baseUrl": "https://rekor.test", "hashAlgorithm": "SHA2_256", "logId": map[string]any{"keyId": f.rekorID},
		"publicKey": map[string]any{"rawBytes": spki(t, f.rekor), "keyDetails": "PKIX_ECDSA_P256_SHA_256", "validFor": win("2000-01-01T00:00:00Z", logEnd)}}
	raw, _ := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		logsField:   []any{rekor},
		"certificateAuthorities": []any{map[string]any{"uri": "https://fulcio.test", "validFor": win(caStart, caEnd),
			"certChain": map[string]any{"certificates": []any{map[string]any{"rawBytes": f.inter.Raw}, map[string]any{"rawBytes": f.rootCert.Raw}}}}}})
	r, err := ParseRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// input is everything the test signs; rows change it before build signs.
type input struct {
	tmpl, parent   *x509.Certificate
	key, signer    crypto.Signer // key in the leaf; key that signs the artifact
	parentKey      crypto.Signer
	extra          []*x509.Certificate // bundle chain form when chain is set
	chain          bool
	media          string
	dsse           bool
	digest         []byte
	payload        []byte
	payloadType    string
	pae            func(string, []byte) []byte
	at             int64
	logKey         *ecdsa.PrivateKey
	logID          []byte
	bodyKind       string
	bodyVersion    string
	bodySignatures int
}

func (f *fixture) input(t testing.TB, dsse bool) input {
	k := p256(t)
	kind := "hashedrekord"
	if dsse {
		kind = "dsse"
	}
	return input{tmpl: leafTmpl([]asn1.RawValue{name(6, identity)}, ext(oidIssuer, der(issuer, "utf8"))),
		parent: f.inter, parentKey: f.interKey, key: k, signer: k, media: v03, dsse: dsse, digest: artifact[:],
		payload: statement, payloadType: "application/vnd.in-toto+json", pae: pae, at: signed.Add(time.Minute).Unix(),
		logKey: f.rekor, logID: f.rekorID, bodyKind: kind, bodyVersion: "0.0.1", bodySignatures: 1}
}

// build signs the artifact or DSSE payload with the leaf and mints a Rekor
// body and signed entry timestamp for it.
func (f *fixture) build(t testing.TB, in input) *bundle {
	leaf := issue(t, in.tmpl, in.parent, in.key, in.parentKey)
	b := &bundle{MediaType: in.media, VerificationMaterial: &material{Certificate: &rawCert{leaf.Raw}}}
	if in.chain {
		cc := &certChain{[]rawCert{{leaf.Raw}}}
		for _, c := range in.extra {
			cc.Certificates = append(cc.Certificates, rawCert{c.Raw})
		}
		b.VerificationMaterial = &material{X509CertificateChain: cc}
	}
	var sig, hash []byte
	if in.dsse {
		sum, ph := sha256.Sum256(in.pae(in.payloadType, in.payload)), sha256.Sum256(in.payload)
		sig, hash = sign(t, in.signer, sum[:]), ph[:]
		b.DSSEEnvelope = &envelope{in.payload, in.payloadType, []envSig{{sig}}}
	} else {
		sig, hash = sign(t, in.signer, in.digest), in.digest
		b.MessageSignature = &messageSig{&digestRef{"SHA2_256", in.digest}, sig}
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	h := map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(hash)}
	spec := map[string]any{"data": map[string]any{"hash": h}, "signature": map[string]any{"content": sig, "publicKey": map[string]any{"content": cert}}}
	if in.bodyKind == "dsse" {
		var sigs []any
		for i := 0; i < in.bodySignatures; i++ {
			sigs = append(sigs, map[string]any{"signature": sig, "verifier": cert})
		}
		spec = map[string]any{"payloadHash": h, "signatures": sigs}
	}
	body, _ := json.Marshal(map[string]any{"apiVersion": in.bodyVersion, "kind": in.bodyKind, "spec": spec})
	logID := sha256.Sum256(spki(t, in.logKey))
	set := sha256.Sum256(fmt.Appendf(nil, `{"body":"%s","integratedTime":%d,"logID":"%x","logIndex":7}`, base64.StdEncoding.EncodeToString(body), in.at, logID))
	b.VerificationMaterial.TlogEntries = []*tlogEntry{{LogIndex: 7, LogID: &logRef{in.logID}, KindVersion: &kindVersion{in.bodyKind, in.bodyVersion},
		IntegratedTime: int64s(in.at), InclusionPromise: &promise{sign(t, in.logKey, set[:])}, CanonicalizedBody: body}}
	return b
}

func entry(b *bundle) *tlogEntry { return b.VerificationMaterial.TlogEntries[0] }

func marshal(t testing.TB, b *bundle) []byte {
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// legacy renders b in the shape cosign sign-blob --new-bundle-format=false --bundle writes.
func legacy(b *bundle) []byte {
	e := entry(b)
	raw, _ := json.Marshal(map[string]any{
		"base64Signature": b.MessageSignature.Signature,
		"cert":            pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.VerificationMaterial.Certificate.RawBytes}),
		"rekorBundle": map[string]any{"SignedEntryTimestamp": e.InclusionPromise.SignedEntryTimestamp, "Payload": map[string]any{
			"body": e.CanonicalizedBody, "integratedTime": e.IntegratedTime, "logIndex": e.LogIndex, "logID": hex.EncodeToString(e.LogID.KeyID)}},
	})
	return raw
}

type row struct {
	name   string
	legacy bool // render the bundle in cosign's local format
	dsse   bool
	in     func(*input)
	post   func(*bundle)
	text   func([]byte) []byte
	san    string // expected identity when not identity
	iss    string // expected issuer when not issuer
	digest []byte
	root   *Root
	ok     bool
}

func TestVerify(t *testing.T) {
	f := newFixture(t)
	withSAN := func(names ...asn1.RawValue) func(*input) {
		return func(in *input) { in.tmpl = leafTmpl(names, ext(oidIssuer, der(issuer, "utf8"))) }
	}
	withIssuer := func(exts ...pkix.Extension) func(*input) {
		return func(in *input) { in.tmpl = leafTmpl([]asn1.RawValue{name(6, identity)}, exts...) }
	}
	at := func(sec int64) func(*input) { return func(in *input) { in.at = sec } }
	var sameKey crypto.Signer
	otherDigest := f.input(t, false)
	otherDigest.digest = other[:]
	transplant := func(b *bundle) func(*bundle) {
		return func(x *bundle) { x.VerificationMaterial.TlogEntries = b.VerificationMaterial.TlogEntries }
	}
	rows := []row{
		{name: "good_message", ok: true},
		{name: "good_dsse", dsse: true, ok: true},
		{name: "good_v01_chain", in: func(in *input) { in.media, in.chain, in.extra = v01, true, []*x509.Certificate{f.inter} }, ok: true},
		{name: "good_v02", in: func(in *input) { in.media = v02 }, ok: true},
		{name: "good_chain_leaf_only", in: func(in *input) { in.chain = true }, ok: true},
		{name: "integrated_time_string_valid", text: func(b []byte) []byte {
			s := fmt.Sprint(signed.Add(time.Minute).Unix())
			return bytes.Replace(b, []byte(`"integratedTime":`+s), []byte(`"integratedTime":"`+s+`"`), 1)
		}, ok: true},
		{name: "legacy_good", legacy: true, ok: true},
		{name: "legacy_other_san", legacy: true, san: "https://github.com/other/repo/.github/workflows/x.yml@refs/tags/v1"},
		{name: "legacy_with_media_type_is_protobuf", legacy: true, text: func(b []byte) []byte { return bytes.Replace(b, []byte("{"), []byte(`{"mediaType":"`+v03+`",`), 1) }},
		{name: "digest_absent", post: func(b *bundle) { b.MessageSignature.MessageDigest = nil }, ok: true},
		{name: "leaf_far_past", in: func(in *input) {
			in.tmpl.NotBefore, in.tmpl.NotAfter, in.at = signed.AddDate(-20, 0, 0), signed.AddDate(-20, 0, 0).Add(time.Minute), signed.AddDate(-20, 0, 0).Unix()
		}, ok: true},
		{name: "leaf_far_future", in: func(in *input) {
			in.tmpl.NotBefore, in.tmpl.NotAfter, in.at = signed.AddDate(60, 0, 0), signed.AddDate(60, 0, 0).Add(time.Minute), signed.AddDate(60, 0, 0).Unix()
		}, ok: true},
		{name: "integrated_time_at_not_before", in: at(signed.Unix()), ok: true},
		{name: "integrated_time_at_not_after", in: at(signed.Add(10 * time.Minute).Unix()), ok: true},
		{name: "two_entries_good", post: func(b *bundle) {
			b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, entry(b))
		}, ok: true},
		// signature and payload
		{name: "sig_bit_flip", post: func(b *bundle) { b.MessageSignature.Signature[4] ^= 1 }},
		{name: "sig_trailing_der", post: func(b *bundle) { b.MessageSignature.Signature = append(b.MessageSignature.Signature, 0) }},
		{name: "sig_over_other_digest", in: func(in *input) { in.signer = p256(t) }},
		{name: "digest_swap", digest: other[:]},
		{name: "digest_31", digest: artifact[:31]},
		{name: "digest_33", digest: append(artifact[:], 0)},
		{name: "algo_sha2_384", post: func(b *bundle) { b.MessageSignature.MessageDigest.Algorithm = "SHA2_384" }},
		{name: "algo_lowercase", post: func(b *bundle) { b.MessageSignature.MessageDigest.Algorithm = "sha256" }},
		{name: "algo_empty", post: func(b *bundle) { b.MessageSignature.MessageDigest.Algorithm = "" }},
		{name: "dsse_payload_swap", dsse: true, post: func(b *bundle) { b.DSSEEnvelope.Payload = []byte(`{"_type":"y"}`) }},
		{name: "dsse_payload_unpadded", dsse: true, text: func(b []byte) []byte {
			p := base64.StdEncoding.EncodeToString(statement)
			return bytes.Replace(b, []byte(p), []byte(strings.TrimRight(p, "=")), 1)
		}},
		{name: "dsse_payload_urlsafe", dsse: true, text: func(b []byte) []byte {
			p := base64.StdEncoding.EncodeToString(statement)
			return bytes.Replace(b, []byte(p), []byte(base64.URLEncoding.EncodeToString(statement)), 1)
		}},
		{name: "dsse_payloadtype_swap", dsse: true, post: func(b *bundle) { b.DSSEEnvelope.PayloadType = "application/json" }},
		{name: "dsse_pae_len", dsse: true, in: func(in *input) {
			in.pae = func(pt string, p []byte) []byte {
				return append(fmt.Appendf(nil, "DSSEv1 %d %s %d ", len(pt), pt, len(base64.StdEncoding.EncodeToString(p))), p...)
			}
		}},
		{name: "dsse_no_signatures", dsse: true, post: func(b *bundle) { b.DSSEEnvelope.Signatures = nil }},
		{name: "dsse_two_sigs", dsse: true, post: func(b *bundle) {
			b.DSSEEnvelope.Signatures = append(b.DSSEEnvelope.Signatures, b.DSSEEnvelope.Signatures[0])
		}},
		{name: "dsse_sig_by_other_key", dsse: true, in: func(in *input) { in.signer = p256(t) }},
		{name: "dsse_empty_payload", dsse: true, post: func(b *bundle) { b.DSSEEnvelope.Payload = nil }},
		{name: "both_kinds", dsse: true, post: func(b *bundle) { b.MessageSignature = &messageSig{Signature: b.DSSEEnvelope.Signatures[0].Sig} }},
		{name: "neither_kind", post: func(b *bundle) { b.MessageSignature = nil }},
		{name: "dsse_null", dsse: true, post: func(b *bundle) { b.DSSEEnvelope = nil }},
		// certificate and chain
		{name: "leaf_unknown_ca", in: func(in *input) { k := p256(t); in.parent, in.parentKey = issue(t, caTmpl(9), nil, k, nil), k }},
		{name: "leaf_by_leaf", in: func(in *input) {
			k := p256(t)
			in.parent, in.parentKey = issue(t, leafTmpl(nil), f.inter, k, f.interKey), k
			in.chain, in.extra = true, []*x509.Certificate{in.parent}
		}},
		{name: "leaf_is_ca", in: func(in *input) { in.tmpl.IsCA, in.tmpl.BasicConstraintsValid = true, true }},
		{name: "leaf_no_codesigning_eku", in: func(in *input) { in.tmpl.ExtKeyUsage = nil }},
		{name: "leaf_no_digital_signature", in: func(in *input) { in.tmpl.KeyUsage = x509.KeyUsageKeyEncipherment }},
		{name: "leaf_before_ca_window", root: f.tooEarly},
		{name: "leaf_after_ca_window", root: f.tooLate},
		{name: "bundle_chain_as_anchor", in: func(in *input) {
			k := p256(t)
			in.parent, in.parentKey = issue(t, caTmpl(9), nil, k, nil), k
			in.media, in.chain, in.extra = v01, true, []*x509.Certificate{in.parent}
		}},
		{name: "chain_too_long", in: func(in *input) {
			in.chain = true
			for i := 0; i < 10; i++ {
				in.extra = append(in.extra, f.inter)
			}
		}},
		{name: "leaf_ed25519", in: func(in *input) { _, k, _ := ed25519.GenerateKey(rand.Reader); in.key = k }},
		{name: "leaf_p384", in: func(in *input) { k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader); in.key, in.signer = k, k }},
		{name: "publickey_material", post: func(b *bundle) { b.VerificationMaterial.PublicKey = &struct{}{} }},
		{name: "cert_not_der", post: func(b *bundle) { b.VerificationMaterial.Certificate.RawBytes = []byte("nope") }},
		{name: "cert_trailing_byte", post: func(b *bundle) {
			b.VerificationMaterial.Certificate.RawBytes = append(b.VerificationMaterial.Certificate.RawBytes, 0)
		}},
		{name: "cert_and_chain", post: func(b *bundle) {
			b.VerificationMaterial.X509CertificateChain = &certChain{[]rawCert{*b.VerificationMaterial.Certificate}}
		}},
		{name: "null_material", post: func(b *bundle) { b.VerificationMaterial = nil }},
		// identity and issuer
		{name: "san_second_uri", in: withSAN(name(6, identity), name(6, identity+".evil"))},
		{name: "san_dns", in: withSAN(name(2, identity))},
		{name: "san_email", in: withSAN(name(1, identity))},
		{name: "san_uri_plus_dns", in: withSAN(name(6, identity), name(2, "x"))},
		{name: "san_none", in: withSAN()},
		{name: "san_prefix", in: withSAN(name(6, identity[:len(identity)-3]))},
		{name: "san_superstring_evil", san: identity + ".evil"},
		{name: "san_superstring_fragment", san: identity + "#x"},
		{name: "san_superstring_query", san: identity + "?x"},
		{name: "san_case", in: withSAN(name(6, strings.Replace(identity, "github", "GitHub", 1)))},
		{name: "san_percent_encoded", in: withSAN(name(6, strings.Replace(identity, "openai", "%6fpenai", 1)))},
		{name: "san_userinfo", in: withSAN(name(6, strings.Replace(identity, "https://", "https://user@", 1)))},
		{name: "san_ref_swap", san: strings.Replace(identity, "refs/tags", "refs/heads", 1)},
		{name: "issuer_old_oid_only", in: withIssuer(ext(oidOldIssuer, []byte(issuer)))},
		{name: "issuer_missing", in: withIssuer()},
		{name: "issuer_wrong", iss: "https://accounts.google.com"},
		{name: "issuer_other_tag", in: withIssuer(ext(oidIssuer, der(issuer, "ia5")))},
		{name: "issuer_trailing_bytes", in: withIssuer(ext(oidIssuer, append(der(issuer, "utf8"), 0)))},
		// Rekor and time
		{name: "no_tlog_entries", post: func(b *bundle) { b.VerificationMaterial.TlogEntries = nil }},
		{name: "proof_only_no_promise", post: func(b *bundle) { entry(b).InclusionPromise = nil }},
		{name: "null_logid", post: func(b *bundle) { entry(b).LogID = nil }},
		{name: "null_entry", post: func(b *bundle) { b.VerificationMaterial.TlogEntries = []*tlogEntry{nil} }},
		{name: "set_other_key", in: func(in *input) { in.logKey = p256(t) }},
		{name: "set_bit_flip", post: func(b *bundle) { entry(b).InclusionPromise.SignedEntryTimestamp[4] ^= 1 }},
		{name: "set_logindex_changed", post: func(b *bundle) { entry(b).LogIndex++ }},
		{name: "set_time_changed", post: func(b *bundle) { entry(b).IntegratedTime++ }},
		{name: "set_body_changed", post: func(b *bundle) { entry(b).CanonicalizedBody[2] ^= 1 }},
		{name: "keyid_unknown", in: func(in *input) { in.logID = other[:] }},
		{name: "keyid_wrong_length", in: func(in *input) { in.logID = f.rekorID[:31] }},
		{name: "keyid_empty", in: func(in *input) { in.logID = nil }},
		{name: "keyid_of_ctlog", root: f.ctOnly},
		{name: "log_key_window_ended", root: f.logEnded},
		{name: "integrated_time_before_not_before", in: at(signed.Unix() - 1)},
		{name: "integrated_time_after_not_after", in: at(signed.Add(10*time.Minute).Unix() + 1)},
		{name: "integrated_time_zero", in: at(0)},
		{name: "integrated_time_negative", in: at(-1)},
		{name: "integrated_time_overflow", text: func(b []byte) []byte {
			return bytes.Replace(b, fmt.Appendf(nil, `"integratedTime":%d`, signed.Add(time.Minute).Unix()), []byte(`"integratedTime":9223372036854775808`), 1)
		}},
		{name: "body_transplant_other_leaf", post: transplant(f.build(t, f.input(t, false)))},
		{name: "body_transplant_other_digest", post: transplant(f.build(t, otherDigest))},
		{name: "body_cert_swap_same_key", in: func(in *input) { sameKey = in.key }, post: func(b *bundle) {
			b.VerificationMaterial.Certificate = &rawCert{issue(t, leafTmpl([]asn1.RawValue{name(6, identity)}, ext(oidIssuer, der(issuer, "utf8"))), f.inter, sameKey, f.interKey).Raw}
		}},
		{name: "body_kind_mismatch_dsse_bundle", dsse: true, in: func(in *input) { in.bodyKind = "hashedrekord" }},
		{name: "body_kind_mismatch_message_bundle", in: func(in *input) { in.bodyKind = "dsse" }},
		{name: "body_version_002", in: func(in *input) { in.bodyVersion = "0.0.2" }},
		{name: "body_two_signatures", dsse: true, in: func(in *input) { in.bodySignatures = 2 }},
		{name: "kindversion_intoto", post: func(b *bundle) { entry(b).KindVersion.Kind = "intoto" }},
		{name: "two_entries_one_bad", post: func(b *bundle) {
			bad := *entry(b)
			bad.InclusionPromise = &promise{append([]byte{}, bad.InclusionPromise.SignedEntryTimestamp...)}
			bad.InclusionPromise.SignedEntryTimestamp[4] ^= 1
			b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, &bad)
		}},
		{name: "entries_too_many", post: func(b *bundle) {
			for i := 0; i < 10; i++ {
				b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, entry(b))
			}
		}},
		// JSON and parser
		{name: "mediatype_unknown", post: func(b *bundle) { b.MediaType = "application/json" }},
		{name: "mediatype_missing", post: func(b *bundle) { b.MediaType = "" }},
		{name: "bundle_oversize", text: func(b []byte) []byte { return append(b, bytes.Repeat([]byte(" "), maxBundle)...) }},
		{name: "json_deep_nesting", text: func([]byte) []byte { return []byte(strings.Repeat("[", 10000) + strings.Repeat("]", 10000)) }},
		{name: "trailing_bytes", text: func(b []byte) []byte { return append(b, 'x') }},
		{name: "empty_input", text: func([]byte) []byte { return nil }},
		{name: "empty_object", text: func([]byte) []byte { return []byte("{}") }},
		{name: "json_null", text: func([]byte) []byte { return []byte("null") }},
		{name: "json_array", text: func([]byte) []byte { return []byte("[]") }},
		{name: "wrong_types", text: func([]byte) []byte { return []byte(`{"mediaType":1,"verificationMaterial":[]}`) }},
		{name: "identity_empty", san: "\x00"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			in := f.input(t, r.dsse)
			if r.in != nil {
				r.in(&in)
			}
			b := f.build(t, in)
			if r.post != nil {
				r.post(b)
			}
			raw := marshal(t, b)
			if r.legacy {
				raw = legacy(b)
			}
			if r.text != nil {
				raw = r.text(raw)
			}
			id, digest, root := Identity{identity, issuer}, artifact[:], f.root
			if r.san == "\x00" {
				id.SAN = ""
			} else if r.san != "" {
				id.SAN = r.san
			}
			if r.iss != "" {
				id.Issuer = r.iss
			}
			if r.digest != nil {
				digest = r.digest
			}
			if r.root != nil {
				root = r.root
			}
			start := time.Now()
			payload, payloadType, err := Verify(root, raw, id, digest)
			if (err == nil) != r.ok {
				t.Fatalf("got %v, want ok=%v", err, r.ok)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("took %v", d)
			}
			if r.ok && r.dsse && (!bytes.Equal(payload, statement) || payloadType != "application/vnd.in-toto+json") {
				t.Fatalf("payload %q type %q", payload, payloadType)
			}
			if r.ok && !r.dsse && payload != nil {
				t.Fatalf("message bundle returned a payload")
			}
		})
	}
}

func TestParseRoot(t *testing.T) {
	f := newFixture(t)
	good, _ := json.Marshal(map[string]any{"tlogs": []any{}, "certificateAuthorities": []any{}})
	badCert, _ := json.Marshal(map[string]any{"certificateAuthorities": []any{map[string]any{"certChain": map[string]any{"certificates": []any{map[string]any{"rawBytes": "AAAA"}}}}}})
	emptyChain, _ := json.Marshal(map[string]any{"certificateAuthorities": []any{map[string]any{"certChain": map[string]any{}}}})
	badKey, _ := json.Marshal(map[string]any{"tlogs": []any{map[string]any{"publicKey": map[string]any{"rawBytes": "AAAA"}}}})
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	edKey, _ := json.Marshal(map[string]any{"tlogs": []any{map[string]any{"publicKey": map[string]any{"rawBytes": spki(t, ed)}}}})
	for _, tc := range []struct {
		name string
		raw  []byte
		ok   bool
		logs int
	}{
		{"empty_root", good, true, 0},
		{"ed25519_key_skipped", edKey, true, 0},
		{"bad_cert", badCert, false, 0},
		{"empty_chain", emptyChain, false, 0},
		{"bad_key", badKey, false, 0},
		{"not_json", []byte("{"), false, 0},
		{"null", []byte("null"), true, 0},
		{"too_large", append(good, bytes.Repeat([]byte(" "), maxRoot)...), false, 0},
	} {
		r, err := ParseRoot(tc.raw)
		if (err == nil) != tc.ok || (r != nil && len(r.logs) != tc.logs) {
			t.Errorf("%s: got %v %+v, want ok=%v", tc.name, err, r, tc.ok)
		}
	}
	if len(f.root.logs) != 1 || len(f.root.cas) != 1 || len(f.ctOnly.logs) != 0 {
		t.Fatalf("fixture root: %d logs, %d CAs; ctlog-only root: %d logs", len(f.root.logs), len(f.root.cas), len(f.ctOnly.logs))
	}
}

// TestPublicRoot proves the embedded snapshot parses and that a Rekor key's
// keyId is the SHA-256 of its SPKI, as rekor.sigstore.dev's is.
func TestPublicRoot(t *testing.T) {
	r := PublicRoot()
	if len(r.cas) == 0 || len(r.logs) == 0 {
		t.Fatalf("%d CAs, %d log keys", len(r.cas), len(r.logs))
	}
	for _, l := range r.logs {
		if hex.EncodeToString(l.keyID) == l.logID {
			return
		}
	}
	t.Fatal("no log key whose keyId is the SHA-256 of its SPKI")
}

// signedMaterial is the leaf DER, Rekor body and signed entry timestamp of a bundle that verified.
func signedMaterial(t testing.TB, raw []byte) []byte {
	var b bundle
	err := json.Unmarshal(raw, &b)
	if err == nil && b.MediaType == "" {
		b, err = cosignBundle(raw)
	}
	if err != nil {
		t.Fatal(err)
	}
	certs, err := parseCerts(b.VerificationMaterial)
	if err != nil {
		t.Fatal(err)
	}
	e := entry(&b)
	return bytes.Join([][]byte{certs[0].Raw, e.CanonicalizedBody, e.InclusionPromise.SignedEntryTimestamp}, nil)
}

func FuzzParse(f *testing.F) {
	fx := newFixture(f)
	var seeds [][]byte
	for _, dsse := range []bool{false, true} {
		seeds = append(seeds, marshal(f, fx.build(f, fx.input(f, dsse))))
	}
	seeds = append(seeds, legacy(fx.build(f, fx.input(f, false))))
	id := Identity{identity, issuer}
	for _, s := range seeds {
		f.Add(s)
	}
	for _, s := range []string{"", "{}", "null", `{"verificationMaterial":null}`, `{"messageSignature":null,"dsseEnvelope":null}`,
		`{"verificationMaterial":{"tlogEntries":[null,{"logId":null,"inclusionPromise":null}]}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, err := Verify(fx.root, data, id, artifact[:])
		if err != nil {
			return
		}
		// A success must carry a seed's exact leaf, Rekor body and signed entry timestamp.
		for _, s := range seeds {
			if bytes.Equal(signedMaterial(t, data), signedMaterial(t, s)) {
				return
			}
		}
		t.Fatalf("verified a bundle with no seed's signed material: %q", data)
	})
}
