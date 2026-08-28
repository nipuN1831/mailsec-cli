package header_test

import (
	"testing"

	"github.com/nipun/mailsec/internal/header"
)

func TestParseDomain_standard_from(t *testing.T) {
	raw := "From: John Doe <john@example.com>\r\nSubject: Test\r\n"
	domain, err := header.ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domain != "example.com" {
		t.Errorf("want example.com, got %s", domain)
	}
}

func TestParseDomain_bare_address(t *testing.T) {
	raw := "From: john@example.com\r\nSubject: Test\r\n"
	domain, err := header.ParseDomain(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domain != "example.com" {
		t.Errorf("want example.com, got %s", domain)
	}
}

func TestParseDomain_missing_from(t *testing.T) {
	raw := "Subject: Test\r\n"
	_, err := header.ParseDomain(raw)
	if err == nil {
		t.Error("want error for missing From header")
	}
}

func TestParseDKIMSelector_found(t *testing.T) {
	raw := "DKIM-Signature: v=1; a=rsa-sha256; s=google; d=gmail.com;\r\n"
	sel := header.ParseDKIMSelector(raw)
	if sel != "google" {
		t.Errorf("want google, got %s", sel)
	}
}

func TestParseDKIMSelector_not_found(t *testing.T) {
	raw := "From: user@example.com\r\n"
	sel := header.ParseDKIMSelector(raw)
	if sel != "default" {
		t.Errorf("want default, got %s", sel)
	}
}

func TestParseDKIMSelector_folded_header(t *testing.T) {
	// RFC 5322 folded header: s= tag on continuation line
	raw := "DKIM-Signature: v=1; a=rsa-sha256;\r\n s=google; d=gmail.com;\r\n"
	sel := header.ParseDKIMSelector(raw)
	if sel != "google" {
		t.Errorf("want google, got %s", sel)
	}
}

func TestParseDKIMSelector_mixed_case_header(t *testing.T) {
	// Header name should be case-insensitive
	raw := "Dkim-Signature: v=1; a=rsa-sha256; s=example; d=example.com;\r\n"
	sel := header.ParseDKIMSelector(raw)
	if sel != "example" {
		t.Errorf("want example, got %s", sel)
	}
}

func TestParseDKIMSelector_body_injection_prevented(t *testing.T) {
	// Regression: body starting with space should not be spliced into headers.
	// DKIM-Signature with no s= tag, blank line, body with " s=attackercontrolled".
	raw := "DKIM-Signature: v=1; a=rsa-sha256; d=example.com;\r\n\r\n s=attackercontrolled; more text\r\n"
	sel := header.ParseDKIMSelector(raw)
	if sel != "default" {
		t.Errorf("want default (body should not be parsed), got %s", sel)
	}
}
