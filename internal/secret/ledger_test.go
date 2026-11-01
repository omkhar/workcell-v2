// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package secret

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

const ts = `"time":"2026-10-16T00:00:00Z"`

// known is the test session's grants: one secret sent in either of two headers.
func known(credential, host, header string) bool {
	return credential == "anthropic" && host == "api.anthropic.com" && (header == "x-api-key" || header == "authorization")
}

func fold(t *testing.T, log string) string {
	t.Helper()
	records, err := LedgerAuditRecords(strings.NewReader(log), known)
	if err != nil || len(records) != 1 {
		t.Fatalf("LedgerAuditRecords(%q) = %q, %v", log, records, err)
	}
	return records[0]
}

// TestLedgerAuditRecordsCountsEachLine folds each line the broker writes as a
// grant or a denial, and each other line as malformed. The ledger is
// untrusted, so no line is dropped in silence.
func TestLedgerAuditRecordsCountsEachLine(t *testing.T) {
	const (
		granted   = "credential_broker_summary status=complete granted=1 denied=0 malformed_lines=0"
		denied    = "credential_broker_summary status=complete granted=0 denied=1 malformed_lines=0"
		malformed = "credential_broker_summary status=malformed granted=0 denied=0 malformed_lines=1"
	)
	for _, tc := range []struct{ line, want string }{
		{`{` + ts + `,"host":"api.anthropic.com","header":"authorization","credential":"anthropic","result":"granted"}`, granted},
		{`{` + ts + `,"host":"api.anthropic.com","header":"x-api-key","credential":"anthropic","result":"granted"}`, granted},
		{`{` + ts + `,"result":"bad_token"}`, denied},
		{`{` + ts + `,"host":"evil.example","header":"x-api-key","result":"not_granted"}`, denied},
		{`{` + ts + `,"result":"rate_limited"}`, denied},
		{`{` + ts + `,"result":"peer_rejected"}`, denied},
		{`{` + ts + `,"result":"malformed"}`, denied},
		{``, malformed},
		{`not json`, malformed},
		{`{` + ts + `,"result":"granted","credential":"anthropic","host":"evil.example","header":"x-api-key"}`, malformed},
		{`{` + ts + `,"result":"granted","credential":"anthropic","host":"api.anthropic.com","header":"x-goog-api-key"}`, malformed},
		{`{` + ts + `,"result":"granted","credential":"other","host":"api.anthropic.com","header":"x-api-key"}`, malformed},
		{`{` + ts + `,"result":"granted"}`, malformed},
		{`{` + ts + `,"result":"not_granted","credential":"anthropic"}`, malformed},
		{`{` + ts + `,"result":"log_failed"}`, malformed},
		{`{` + ts + `,"result":"unknown"}`, malformed},
		{`{"time":"yesterday","result":"bad_token"}`, malformed},
		{`{"result":"bad_token"}`, malformed},
		{`{` + ts + `,"result":"bad_token","value":"sk-a"}`, malformed},
		{`{` + ts + `,"result":"bad_token"} {}`, malformed},
		{`{` + ts + `,"result":"bad_token"}x`, malformed},
		{`{` + ts + `,"result":"granted","credential":"bogus","credential":"anthropic","host":"api.anthropic.com","header":"x-api-key"}`, malformed},
		{`{` + ts + `,"result":"granted","result":"bad_token"}`, malformed},
		{`[` + ts + `]`, malformed},
	} {
		if got := fold(t, tc.line+"\n"); got != tc.want {
			t.Errorf("line %q: got %q, want %q", tc.line, got, tc.want)
		}
	}
}

// TestLedgerAuditRecordsOfAnEmptyLedger is a session that sent no request.
func TestLedgerAuditRecordsOfAnEmptyLedger(t *testing.T) {
	if got, want := fold(t, ""), "credential_broker_summary status=complete granted=0 denied=0 malformed_lines=0"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestLedgerAuditRecordsReadsWhatTheBrokerWrites folds a ledger that a real
// broker wrote: one grant and one denial of each kind it can record.
func TestLedgerAuditRecordsReadsWhatTheBrokerWrites(t *testing.T) {
	log := &syncBuffer{}
	b := newTestBroker(t, log)
	ctx := context.Background()
	for _, host := range []string{"api.anthropic.com", "evil.example", strings.Repeat("h", maxLineBytes+1)} {
		_, _ = b.Lookup(ctx, host, "x-api-key")
	}
	b.windowStart, b.count = time.Now(), rateLimit
	_, _ = b.Lookup(ctx, "api.anthropic.com", "x-api-key")
	if got, want := fold(t, log.String()), "credential_broker_summary status=complete granted=1 denied=3 malformed_lines=0"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestLedgerAuditRecordsRefusesALineTheBrokerCannotWrite fails the read on a
// 32 KiB line instead of folding a partial line, and still folds the longest
// line the broker can write: a lookup at the size limit whose host is all
// control characters, which JSON escapes to 6 bytes each.
func TestLedgerAuditRecordsRefusesALineTheBrokerCannotWrite(t *testing.T) {
	line := `{` + ts + `,"result":"bad_token","host":"` + strings.Repeat("a", 32<<10) + `"}`
	if records, err := LedgerAuditRecords(strings.NewReader(line+"\n"), known); err == nil {
		t.Fatalf("LedgerAuditRecords = %q, want an error for a line over the cap", records)
	}
	log := &syncBuffer{}
	_, _ = newTestBroker(t, log).Lookup(context.Background(), strings.Repeat("\x01", maxLineBytes-len("x-api-key")), "x-api-key")
	if got, want := fold(t, log.String()), "credential_broker_summary status=complete granted=0 denied=1 malformed_lines=0"; got != want {
		t.Fatalf("a %d-byte line: got %q, want %q", log.Len(), got, want)
	}
}

// TestLedgerAuditRecordsStopsAtTheRecordLimit bounds the read: past the
// record limit the summary stops counting and says so.
func TestLedgerAuditRecordsStopsAtTheRecordLimit(t *testing.T) {
	line := `{` + ts + `,"result":"bad_token"}` + "\n"
	for _, tc := range []struct {
		lines int
		want  string
	}{
		{5, "credential_broker_summary status=truncated granted=0 denied=3 malformed_lines=0"},
		{3, "credential_broker_summary status=complete granted=0 denied=3 malformed_lines=0"},
	} {
		records, err := ledgerAuditRecords(strings.NewReader(strings.Repeat(line, tc.lines)), known, 3)
		if err != nil || len(records) != 1 || records[0] != tc.want {
			t.Errorf("%d lines: got %q, %v; want [%q]", tc.lines, records, err, tc.want)
		}
	}
}

// TestStartAuditRecordNamesTheSource pins the start record of a secret.
func TestStartAuditRecordNamesTheSource(t *testing.T) {
	for _, tc := range []struct{ name, source, want string }{
		{"anthropic", "keychain:workcell/anthropic", `credential_broker_start name=anthropic source="keychain:workcell/anthropic"`},
		{"gh", "file:/home/me/my token", `credential_broker_start name=gh source="file:/home/me/my token"`},
		{"x", "cmd:/bin/pass\n\x00\u00e9", `credential_broker_start name=x source="cmd:/bin/pass\n\x00\u00e9"`},
	} {
		if got := StartAuditRecord(tc.name, tc.source); got != tc.want {
			t.Errorf("StartAuditRecord(%q, %q) = %q, want %q", tc.name, tc.source, got, tc.want)
		}
	}
}

// FuzzLedgerAuditRecords folds any bytes into one printable summary that never
// counts more lines than it was fed, nor more than the record limit.
func FuzzLedgerAuditRecords(f *testing.F) {
	const limit = 4
	f.Add([]byte(`{` + ts + `,"host":"api.anthropic.com","header":"x-api-key","credential":"anthropic","result":"granted"}` + "\n"))
	f.Add([]byte(`{` + ts + `,"result":"not_granted"}` + "\n" + `{` + ts + `,"result":"bad_token"}`))
	f.Add([]byte(`{` + ts + `,"result":"granted","credential":"x","credential":"anthropic","host":"api.anthropic.com","header":"x-api-key"}`))
	f.Add([]byte(`{` + ts + `,"result":"bad_token","host":"` + strings.Repeat("a", maxLedgerLineBytes) + `"}`))
	f.Add([]byte("\x00\xff{[\"\r\n\n\n\n\n\n"))
	f.Fuzz(func(t *testing.T, log []byte) {
		got, err := ledgerAuditRecords(bytes.NewReader(log), known, limit)
		if err != nil {
			if got != nil {
				t.Fatalf("records %q with error %v", got, err)
			}
			return
		}
		if len(got) != 1 || !strings.HasPrefix(got[0], "credential_broker_summary ") {
			t.Fatalf("records = %q", got)
		}
		for _, c := range []byte(got[0]) {
			if c < ' ' || c > '~' {
				t.Fatalf("record %q holds byte %#x", got[0], c)
			}
		}
		var status string
		var granted, denied, malformed uint64
		if _, err := fmt.Sscanf(got[0], "credential_broker_summary status=%s granted=%d denied=%d malformed_lines=%d", &status, &granted, &denied, &malformed); err != nil {
			t.Fatalf("record %q: %v", got[0], err)
		}
		lines := uint64(bytes.Count(log, []byte("\n")))
		if len(log) > 0 && log[len(log)-1] != '\n' {
			lines++
		}
		if sum := granted + denied + malformed; sum > min(lines, limit) {
			t.Fatalf("record %q counts %d lines of %d", got[0], sum, lines)
		}
		if (status == "complete") != (malformed == 0 && lines <= limit) {
			t.Fatalf("record %q from %d lines", got[0], lines)
		}
	})
}
