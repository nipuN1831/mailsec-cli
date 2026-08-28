package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nipun/mailsec/internal/checker"
	"github.com/nipun/mailsec/internal/report"
)

func TestPrint_contains_domain(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{Name: "SPF", Status: checker.StatusPass, Detail: "v=spf1 -all"},
	}
	report.Print(&buf, "example.com", results)
	if !strings.Contains(buf.String(), "example.com") {
		t.Error("output should contain domain name")
	}
}

func TestPrint_shows_all_checks(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{Name: "SPF", Status: checker.StatusPass},
		{Name: "DKIM", Status: checker.StatusNone},
		{Name: "DMARC", Status: checker.StatusFail},
	}
	report.Print(&buf, "example.com", results)
	out := buf.String()
	for _, name := range []string{"SPF", "DKIM", "DMARC"} {
		if !strings.Contains(out, name) {
			t.Errorf("output should contain %s", name)
		}
	}
}

func TestPrintJSON_valid_json(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{Name: "SPF", Status: checker.StatusPass, Detail: "v=spf1 -all"},
	}
	err := report.PrintJSON(&buf, "example.com", results)
	if err != nil {
		t.Fatalf("PrintJSON returned error: %v", err)
	}
	if !strings.Contains(buf.String(), `"domain"`) {
		t.Error("JSON output should contain domain field")
	}
}
