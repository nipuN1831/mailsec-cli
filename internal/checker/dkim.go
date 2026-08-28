package checker

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

type DKIMChecker struct {
	Selector string
	resolver *net.Resolver
}

func NewDKIMChecker(selector string) *DKIMChecker {
	if selector == "" {
		selector = "default"
	}
	return &DKIMChecker{Selector: selector, resolver: net.DefaultResolver}
}

func (d *DKIMChecker) Check(ctx context.Context, domain string) Result {
	host := fmt.Sprintf("%s._domainkey.%s", d.Selector, domain)
	records, err := d.resolver.LookupTXT(ctx, host)
	if err != nil {
		return Result{
			Name:   "DKIM",
			Status: StatusNone,
			Detail: fmt.Sprintf("no DKIM record for selector=%s", d.Selector),
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
	keyBits := estimateKeyBits(record)
	return fmt.Sprintf("selector=%s key≈%d-bit RSA", selector, keyBits)
}

func estimateKeyBits(record string) int {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			b64 := strings.TrimPrefix(part, "p=")
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return 0
			}
			return len(decoded) * 8
		}
	}
	return 0
}
