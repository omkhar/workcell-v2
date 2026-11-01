// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: credbroker/ledger.go

package secret

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// maxLineBytes bounds one broker request. The ledger writer (U-400) reuses it.
const maxLineBytes = 4096

// maxLedgerLineBytes is above the longest line the broker can write: a
// request is at most maxLineBytes, and JSON escaping grows a byte to at most 6.
const maxLedgerLineBytes = 8 * maxLineBytes

// maxLedgerRecords bounds the summary read. The broker's request budgets allow
// about 864,000 lines in the 24-hour session CA lifetime; past this limit the
// summary stops and reports status=truncated.
const maxLedgerRecords = 1_000_000

// Ledger results: one grant, and each denial the broker records.
const (
	resultGranted      = "granted"
	resultBadToken     = "bad_token"
	resultRateLimited  = "rate_limited"
	resultNotGranted   = "not_granted"
	resultPeerRejected = "peer_rejected"
	resultMalformed    = "malformed"
)

// ledgerRecord is one ledger line. The writer must emit these keys in this
// order, so the reader reads back exactly what the broker writes.
type ledgerRecord struct {
	Time       string `json:"time"`
	Host       string `json:"host,omitempty"`
	Header     string `json:"header,omitempty"`
	Credential string `json:"credential,omitempty"`
	Result     string `json:"result"`
}

// StartAuditRecord is the session audit record for a secret the broker
// serves: its name and its source. The source is quoted, as it may hold a
// space.
func StartAuditRecord(name, source string) string {
	return fmt.Sprintf("credential_broker_start name=%s source=%+q", name, source)
}

// LedgerAuditRecords folds a broker request log into one
// "credential_broker_summary" audit record. The log is read back after the
// session as untrusted input: a line that is not one strict ledger object, a
// grant for which known(credential, host, header) is false, or a denial that
// names a credential counts in malformed_lines, never in silence. known
// answers from the session's [[secret]] rows. A read error, such as a line
// longer than the broker can write, fails the whole read.
func LedgerAuditRecords(log io.Reader, known func(credential, host, header string) bool) ([]string, error) {
	return ledgerAuditRecords(log, known, maxLedgerRecords)
}

func ledgerAuditRecords(log io.Reader, known func(credential, host, header string) bool, maxRecords uint64) ([]string, error) {
	var granted, denied, malformed, lines uint64
	truncated := false
	scanner := bufio.NewScanner(log)
	scanner.Buffer(make([]byte, 0, maxLineBytes), maxLedgerLineBytes)
	for scanner.Scan() {
		if lines == maxRecords {
			truncated = true
			break
		}
		lines++
		record, ok := parseLedgerLine(scanner.Text(), known)
		switch {
		case !ok:
			malformed++
		case record.Result == resultGranted:
			granted++
		default:
			denied++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read credential broker ledger: %w", err)
	}
	status := "complete"
	switch {
	case truncated:
		status = "truncated"
	case malformed > 0:
		status = "malformed"
	}
	return []string{fmt.Sprintf("credential_broker_summary status=%s granted=%d denied=%d malformed_lines=%d", status, granted, denied, malformed)}, nil
}

// parseLedgerLine accepts one ledgerRecord with a valid time and nothing after
// it: a grant of a known (credential, host, header), or a denial with a known
// result and no credential.
func parseLedgerLine(line string, known func(credential, host, header string) bool) (ledgerRecord, bool) {
	var record ledgerRecord
	if !uniqueObjectKeys(line) {
		return record, false
	}
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&record) != nil || dec.InputOffset() != int64(len(line)) {
		return record, false
	}
	if _, err := time.Parse(time.RFC3339Nano, record.Time); err != nil {
		return record, false
	}
	switch record.Result {
	case resultGranted:
		return record, known(record.Credential, record.Host, record.Header)
	case resultBadToken, resultRateLimited, resultNotGranted, resultPeerRejected, resultMalformed:
		return record, record.Credential == ""
	}
	return record, false
}

// uniqueObjectKeys reports whether line is one JSON object whose keys are all
// distinct. encoding/json keeps the last of a repeated key, so a line the
// broker never writes could otherwise pass with a second "credential".
func uniqueObjectKeys(line string) bool {
	dec := json.NewDecoder(strings.NewReader(line))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return false
		}
	}
	return true
}
