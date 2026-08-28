package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nipuN1831/mailsec/internal/checker"
	"github.com/nipuN1831/mailsec/internal/report"
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

func TestPrint_missing_record_is_not_reported_as_secure(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{Name: "SPF", Status: checker.StatusPass, Detail: "v=spf1 -all"},
		{Name: "DKIM", Status: checker.StatusPass, Detail: "selector=s1 key=2048-bit RSA"},
		{Name: "DMARC", Status: checker.StatusNone, Detail: "no DMARC record found"},
	}

	report.Print(&buf, "example.com", results)

	out := buf.String()
	if strings.Contains(out, "SECURE") {
		t.Errorf("a missing DMARC record must not yield a SECURE verdict, got:\n%s", out)
	}
	if !strings.Contains(out, "WEAK") {
		t.Errorf("want a WEAK verdict, got:\n%s", out)
	}
}

func TestPrint_all_pass_is_secure(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{Name: "SPF", Status: checker.StatusPass},
		{Name: "DMARC", Status: checker.StatusPass},
	}

	report.Print(&buf, "example.com", results)

	if !strings.Contains(buf.String(), "SECURE") {
		t.Errorf("want a SECURE verdict when every check passes, got:\n%s", buf.String())
	}
}

func TestPrint_shows_underlying_error(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{
			Name:   "SPF",
			Status: checker.StatusNone,
			Detail: "DNS lookup failed",
			Err:    errors.New("spf: lookup example.com: context deadline exceeded"),
		},
	}

	report.Print(&buf, "example.com", results)

	if !strings.Contains(buf.String(), "context deadline exceeded") {
		t.Errorf("output should surface the underlying error, got:\n%s", buf.String())
	}
}

func TestPrintJSON_includes_error_field(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{
			Name:   "SPF",
			Status: checker.StatusNone,
			Detail: "DNS lookup failed",
			Err:    errors.New("spf: lookup example.com: context deadline exceeded"),
		},
	}

	if err := report.PrintJSON(&buf, "example.com", results); err != nil {
		t.Fatalf("PrintJSON returned error: %v", err)
	}

	spf := decodeCheck(t, buf.Bytes(), "spf")
	if spf["error"] != "spf: lookup example.com: context deadline exceeded" {
		t.Errorf("want the wrapped error in the error field, got %v", spf["error"])
	}
}

func TestPrintJSON_omits_error_field_when_nil(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{Name: "SPF", Status: checker.StatusPass, Detail: "v=spf1 -all"},
	}

	if err := report.PrintJSON(&buf, "example.com", results); err != nil {
		t.Fatalf("PrintJSON returned error: %v", err)
	}

	spf := decodeCheck(t, buf.Bytes(), "spf")
	if _, ok := spf["error"]; ok {
		t.Errorf("error field should be omitted when Err is nil, got %v", spf)
	}
}

func TestPrintJSON_verdict_reflects_missing_record(t *testing.T) {
	var buf bytes.Buffer
	results := []checker.Result{
		{Name: "SPF", Status: checker.StatusPass},
		{Name: "DMARC", Status: checker.StatusNone},
	}

	if err := report.PrintJSON(&buf, "example.com", results); err != nil {
		t.Fatalf("PrintJSON returned error: %v", err)
	}

	var out struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if out.Verdict != string(checker.StatusWarning) {
		t.Errorf("want verdict=warning, got %q", out.Verdict)
	}
}

func decodeCheck(t *testing.T, data []byte, name string) map[string]any {
	t.Helper()
	var out struct {
		Checks map[string]map[string]any `json:"checks"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	check, ok := out.Checks[name]
	if !ok {
		t.Fatalf("no %q entry in checks: %v", name, out.Checks)
	}
	return check
}
