package checker

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

type DKIMChecker struct {
	Selector  string
	lookupTXT lookupFunc
}

func NewDKIMChecker(selector string) *DKIMChecker {
	if selector == "" {
		selector = "default"
	}
	return &DKIMChecker{Selector: selector, lookupTXT: net.DefaultResolver.LookupTXT}
}

func (d *DKIMChecker) Check(ctx context.Context, domain string) Result {
	host := fmt.Sprintf("%s._domainkey.%s", d.Selector, domain)
	records, err := d.lookupTXT(ctx, host)
	if err != nil {
		detail := "DNS lookup failed"
		if isDNSNotFound(err) {
			detail = fmt.Sprintf("no DKIM record for selector=%s", d.Selector)
		}
		return Result{
			Name:   "DKIM",
			Status: StatusNone,
			Detail: detail,
			Err:    fmt.Errorf("dkim: lookup %s: %w", host, err),
		}
	}

	record := strings.Join(records, "")
	if !strings.Contains(record, "v=DKIM1") {
		return Result{Name: "DKIM", Status: StatusNone, Detail: "record found but not a valid DKIM key"}
	}

	if isKeyRevoked(record) {
		return Result{Name: "DKIM", Status: StatusFail, Detail: "key revoked (p= is empty)"}
	}

	return Result{
		Name:   "DKIM",
		Status: StatusPass,
		Detail: dkimDetail(record, d.Selector),
	}
}

func isKeyRevoked(record string) bool {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "p=" {
			return true
		}
	}
	return false
}

func dkimDetail(record, selector string) string {
	return fmt.Sprintf("selector=%s key=%d-bit %s", selector, keyBits(record), parseKeyType(record))
}

// keyBits reports the public key strength from the p= tag. The tag holds a DER
// SubjectPublicKeyInfo, so the encoded byte length overstates the real key size
// by the size of the ASN.1 wrapper; parsing it gives the true figure.
func keyBits(record string) int {
	decoded, err := decodePublicKey(record)
	if err != nil {
		return 0
	}

	pub, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		// A malformed key still deserves a report, so approximate rather than
		// fail — this is a diagnostic tool, not a validator.
		return len(decoded) * 8
	}

	switch key := pub.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case ed25519.PublicKey:
		return 256
	default:
		return len(decoded) * 8
	}
}

func decodePublicKey(record string) ([]byte, error) {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			b64 := strings.TrimPrefix(part, "p=")
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("dkim: decode p= tag: %w", err)
			}
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("dkim: no p= tag in record")
}

func parseKeyType(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "k=") {
			kType := strings.TrimPrefix(part, "k=")
			return strings.ToUpper(kType)
		}
	}
	return "RSA"
}
