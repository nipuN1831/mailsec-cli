package checker

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestDMARCPolicyStatus(t *testing.T) {
	cases := []struct {
		policy string
		want   Status
	}{
		{"reject", StatusPass},
		{"quarantine", StatusWarning},
		{"none", StatusFail},
		{"", StatusFail},
	}

	for _, tc := range cases {
		got := dmarcPolicyStatus(tc.policy)
		if got != tc.want {
			t.Errorf("dmarcPolicyStatus(%q) = %s, want %s", tc.policy, got, tc.want)
		}
	}
}

func TestDMARCTag(t *testing.T) {
	record := "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=50"

	if got := dmarcTag(record, "p"); got != "reject" {
		t.Errorf("dmarcTag(p) = %q, want reject", got)
	}
	if got := dmarcTag(record, "rua"); got != "mailto:dmarc@example.com" {
		t.Errorf("dmarcTag(rua) = %q, want the mailto target", got)
	}
	if got := dmarcTag(record, "sp"); got != "" {
		t.Errorf("dmarcTag(sp) = %q, want empty for an absent tag", got)
	}
}

func TestDMARCPct(t *testing.T) {
	cases := []struct {
		record string
		want   int
	}{
		{"v=DMARC1; p=reject; pct=50", 50},
		{"v=DMARC1; p=reject", 100},
		{"v=DMARC1; p=reject; pct=abc", 100},
	}

	for _, tc := range cases {
		if got := dmarcPct(tc.record); got != tc.want {
			t.Errorf("dmarcPct(%q) = %d, want %d", tc.record, got, tc.want)
		}
	}
}

func TestFindDMARCRecord(t *testing.T) {
	records := []string{"unrelated=1", "v=DMARC1; p=reject"}
	if got := findDMARCRecord(records); got != "v=DMARC1; p=reject" {
		t.Errorf("findDMARCRecord = %q, want the DMARC1 record", got)
	}
	if got := findDMARCRecord([]string{"unrelated=1"}); got != "" {
		t.Errorf("findDMARCRecord = %q, want empty when no DMARC1 record", got)
	}
}

func TestDMARCChecker_Check_enforcing_policy(t *testing.T) {
	c := &DMARCChecker{lookupTXT: stubLookup([]string{"v=DMARC1; p=reject; rua=mailto:d@example.com"}, nil)}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusPass {
		t.Fatalf("want StatusPass, got %s", result.Status)
	}
	if !strings.Contains(result.Detail, "policy=reject") || !strings.Contains(result.Detail, "pct=100") {
		t.Errorf("detail should summarise policy and pct, got %q", result.Detail)
	}
	if !strings.Contains(result.Detail, "rua=mailto:d@example.com") {
		t.Errorf("detail should include the reporting address, got %q", result.Detail)
	}
}

func TestDMARCChecker_Check_monitoring_only(t *testing.T) {
	c := &DMARCChecker{lookupTXT: stubLookup([]string{"v=DMARC1; p=none"}, nil)}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusFail {
		t.Errorf("want StatusFail for p=none, got %s", result.Status)
	}
}

func TestDMARCChecker_Check_not_found(t *testing.T) {
	c := &DMARCChecker{lookupTXT: stubLookup(nil, &net.DNSError{Err: "no such host", IsNotFound: true})}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusNone {
		t.Errorf("want StatusNone, got %s", result.Status)
	}
	if result.Detail != "no DMARC record found" {
		t.Errorf("want a not-found detail, got %q", result.Detail)
	}
}

func TestDMARCChecker_Check_transient_failure(t *testing.T) {
	c := &DMARCChecker{lookupTXT: stubLookup(nil, &net.DNSError{Err: "server misbehaving", IsTimeout: true})}

	result := c.Check(context.Background(), "example.com")

	if result.Detail != "DNS lookup failed" {
		t.Errorf("a transient failure must not be reported as an absent policy, got %q", result.Detail)
	}
	if result.Err == nil {
		t.Error("want the lookup error preserved")
	}
}
