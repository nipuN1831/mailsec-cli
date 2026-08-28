package main

import (
	"bytes"
	"strings"
	"testing"
)

// A 1ms timeout makes these tests independent of DNS availability: every lookup
// fails immediately, which still exercises the full stdin → report path.
const fastTimeout = "--timeout=1ms"

func TestRun_reads_piped_headers(t *testing.T) {
	var out bytes.Buffer
	headers := "From: alice@example.com\r\nDKIM-Signature: v=1; s=sel1; d=example.com\r\n"

	err := run([]string{fastTimeout}, strings.NewReader(headers), &out)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !strings.Contains(out.String(), "example.com") {
		t.Errorf("output should report the domain parsed from headers, got:\n%s", out.String())
	}
}

func TestRun_domain_flag_skips_stdin(t *testing.T) {
	var out bytes.Buffer

	err := run([]string{"--domain=example.com", fastTimeout}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !strings.Contains(out.String(), "example.com") {
		t.Errorf("output should report the flag domain, got:\n%s", out.String())
	}
}

func TestRun_surfaces_lookup_errors(t *testing.T) {
	var out bytes.Buffer

	err := run([]string{"--domain=example.com", fastTimeout, "--json"}, strings.NewReader(""), &out)
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if !strings.Contains(out.String(), `"error"`) {
		t.Errorf("timed-out lookups should surface an error field, got:\n%s", out.String())
	}
}

func TestRun_rejects_empty_stdin(t *testing.T) {
	var out bytes.Buffer

	err := run([]string{fastTimeout}, strings.NewReader(""), &out)
	if err == nil {
		t.Fatal("want an error when neither --domain nor headers are supplied")
	}
}

func TestRun_rejects_unknown_flag(t *testing.T) {
	var out bytes.Buffer

	err := run([]string{"--nope"}, strings.NewReader(""), &out)
	if err == nil {
		t.Fatal("want an error for an unknown flag")
	}
}

func TestIsTerminal_false_for_non_file_readers(t *testing.T) {
	if isTerminal(strings.NewReader("")) {
		t.Error("a strings.Reader is not a terminal, so stdin must still be read")
	}
	if isTerminal(bytes.NewReader(nil)) {
		t.Error("a bytes.Reader is not a terminal, so stdin must still be read")
	}
}
