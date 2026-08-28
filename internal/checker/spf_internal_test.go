package checker

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestSPFPolicy(t *testing.T) {
	cases := []struct {
		name   string
		record string
		want   Status
	}{
		{"hard fail", "v=spf1 -all", StatusPass},
		{"soft fail", "v=spf1 ~all", StatusWarning},
		{"pass all", "v=spf1 +all", StatusFail},
		{"neutral all", "v=spf1 ?all", StatusFail},
		{"bare all", "v=spf1 all", StatusFail},
		{"redirect", "v=spf1 redirect=_spf.example.com", StatusWarning},
		{"include resembling all", "v=spf1 include:spf-all.example.com ~all", StatusWarning},
		{"no mechanism", "v=spf1", StatusWarning},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := spfPolicy(tc.record)
			if got != tc.want {
				t.Errorf("spfPolicy(%q) = %s, want %s", tc.record, got, tc.want)
			}
		})
	}
}

func TestSPFPolicy_redirect_detail_names_target(t *testing.T) {
	_, note := spfPolicy("v=spf1 redirect=_spf.example.com")
	if !strings.Contains(note, "redirect=_spf.example.com") {
		t.Errorf("redirect note should name the target, got %q", note)
	}
}

func TestSPFPolicy_hard_fail_beats_earlier_include(t *testing.T) {
	// A token containing "-all" must not be mistaken for the terminal
	// mechanism; here the real mechanism is ~all, so the verdict is a warning.
	got, _ := spfPolicy("v=spf1 include:spf-all.example.com -all")
	if got != StatusPass {
		t.Errorf("want StatusPass when a genuine -all is present, got %s", got)
	}
}

func TestFindSPFRecord(t *testing.T) {
	records := []string{"some-unrelated-txt", "v=spf1 -all"}
	if got := findSPFRecord(records); got != "v=spf1 -all" {
		t.Errorf("findSPFRecord = %q, want the spf1 record", got)
	}
	if got := findSPFRecord([]string{"docusign=abc"}); got != "" {
		t.Errorf("findSPFRecord = %q, want empty when no spf1 record", got)
	}
}

func TestSPFChecker_Check_classifies_record(t *testing.T) {
	c := &SPFChecker{lookupTXT: stubLookup([]string{"v=spf1 -all"}, nil)}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusPass {
		t.Errorf("want StatusPass, got %s", result.Status)
	}
	if result.Err != nil {
		t.Errorf("unexpected error: %v", result.Err)
	}
	if !strings.Contains(result.Detail, "v=spf1 -all") {
		t.Errorf("detail should quote the record, got %q", result.Detail)
	}
}

func TestSPFChecker_Check_not_found(t *testing.T) {
	c := &SPFChecker{lookupTXT: stubLookup(nil, &net.DNSError{Err: "no such host", IsNotFound: true})}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusNone {
		t.Errorf("want StatusNone, got %s", result.Status)
	}
	if result.Detail != "no SPF record found" {
		t.Errorf("want a not-found detail, got %q", result.Detail)
	}
	if result.Err == nil {
		t.Error("want the lookup error preserved")
	}
}

func TestSPFChecker_Check_transient_failure(t *testing.T) {
	c := &SPFChecker{lookupTXT: stubLookup(nil, &net.DNSError{Err: "server misbehaving", IsTimeout: true})}

	result := c.Check(context.Background(), "example.com")

	if result.Detail != "DNS lookup failed" {
		t.Errorf("transient failure must not be reported as a missing record, got %q", result.Detail)
	}
}

func TestSPFChecker_Check_no_spf_among_txt_records(t *testing.T) {
	c := &SPFChecker{lookupTXT: stubLookup([]string{"docusign=abc"}, nil)}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusNone {
		t.Errorf("want StatusNone, got %s", result.Status)
	}
}
