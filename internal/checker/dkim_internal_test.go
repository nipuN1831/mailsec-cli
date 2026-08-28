package checker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func TestKeyBits_rsa_reports_modulus_size(t *testing.T) {
	record := "v=DKIM1; k=rsa; p=" + rsaPublicKeyBase64(t, 2048)

	if got := keyBits(record); got != 2048 {
		t.Errorf("keyBits = %d, want 2048 (the modulus size, not the DER length)", got)
	}
}

func TestKeyBits_rsa_1024(t *testing.T) {
	record := "v=DKIM1; p=" + rsaPublicKeyBase64(t, 1024)

	if got := keyBits(record); got != 1024 {
		t.Errorf("keyBits = %d, want 1024", got)
	}
}

func TestKeyBits_ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshalling ed25519 key: %v", err)
	}
	record := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(der)

	if got := keyBits(record); got != 256 {
		t.Errorf("keyBits = %d, want 256", got)
	}
}

func TestKeyBits_malformed_der_falls_back_to_length(t *testing.T) {
	garbage := []byte("not a DER structure")
	record := "v=DKIM1; p=" + base64.StdEncoding.EncodeToString(garbage)

	want := len(garbage) * 8
	if got := keyBits(record); got != want {
		t.Errorf("keyBits = %d, want the %d-bit fallback approximation", got, want)
	}
}

func TestKeyBits_missing_or_invalid_p_tag(t *testing.T) {
	if got := keyBits("v=DKIM1; k=rsa"); got != 0 {
		t.Errorf("keyBits = %d, want 0 when p= is absent", got)
	}
	if got := keyBits("v=DKIM1; p=!!!not-base64!!!"); got != 0 {
		t.Errorf("keyBits = %d, want 0 when p= is not base64", got)
	}
}

func TestIsKeyRevoked(t *testing.T) {
	if !isKeyRevoked("v=DKIM1; k=rsa; p=") {
		t.Error("empty p= means the key is revoked")
	}
	if isKeyRevoked("v=DKIM1; k=rsa; p=AAAA") {
		t.Error("a populated p= is not revoked")
	}
}

func TestParseKeyType(t *testing.T) {
	if got := parseKeyType("v=DKIM1; k=ed25519; p=AAAA"); got != "ED25519" {
		t.Errorf("parseKeyType = %q, want ED25519", got)
	}
	if got := parseKeyType("v=DKIM1; p=AAAA"); got != "RSA" {
		t.Errorf("parseKeyType = %q, want the RSA default", got)
	}
}

func TestDKIMChecker_Check_valid_key(t *testing.T) {
	record := "v=DKIM1; k=rsa; p=" + rsaPublicKeyBase64(t, 2048)
	c := &DKIMChecker{Selector: "s1", lookupTXT: stubLookup([]string{record}, nil)}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusPass {
		t.Fatalf("want StatusPass, got %s (%s)", result.Status, result.Detail)
	}
	if !strings.Contains(result.Detail, "2048-bit RSA") {
		t.Errorf("detail should report the true key size, got %q", result.Detail)
	}
	if !strings.Contains(result.Detail, "selector=s1") {
		t.Errorf("detail should name the selector, got %q", result.Detail)
	}
}

func TestDKIMChecker_Check_revoked_key(t *testing.T) {
	c := &DKIMChecker{Selector: "s1", lookupTXT: stubLookup([]string{"v=DKIM1; k=rsa; p="}, nil)}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusFail {
		t.Errorf("want StatusFail for a revoked key, got %s", result.Status)
	}
}

func TestDKIMChecker_Check_not_found(t *testing.T) {
	c := &DKIMChecker{Selector: "s1", lookupTXT: stubLookup(nil, &net.DNSError{Err: "no such host", IsNotFound: true})}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusNone {
		t.Errorf("want StatusNone, got %s", result.Status)
	}
	if !strings.Contains(result.Detail, "no DKIM record for selector=s1") {
		t.Errorf("want a not-found detail naming the selector, got %q", result.Detail)
	}
}

func TestDKIMChecker_Check_transient_failure(t *testing.T) {
	c := &DKIMChecker{Selector: "s1", lookupTXT: stubLookup(nil, &net.DNSError{Err: "server misbehaving", IsTimeout: true})}

	result := c.Check(context.Background(), "example.com")

	if result.Detail != "DNS lookup failed" {
		t.Errorf("transient failure must not be reported as a missing record, got %q", result.Detail)
	}
	if result.Err == nil {
		t.Error("want the lookup error preserved")
	}
}

func TestDKIMChecker_Check_non_dkim_record(t *testing.T) {
	c := &DKIMChecker{Selector: "s1", lookupTXT: stubLookup([]string{"some-other-txt"}, nil)}

	result := c.Check(context.Background(), "example.com")

	if result.Status != StatusNone {
		t.Errorf("want StatusNone for a record that is not a DKIM key, got %s", result.Status)
	}
}

func rsaPublicKeyBase64(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating %d-bit RSA key: %v", bits, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshalling RSA public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
