package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type SPFChecker struct {
	lookupTXT lookupFunc
}

func NewSPFChecker() *SPFChecker {
	return &SPFChecker{lookupTXT: net.DefaultResolver.LookupTXT}
}

func (s *SPFChecker) Check(ctx context.Context, domain string) Result {
	records, err := s.lookupTXT(ctx, domain)
	if err != nil {
		detail := "DNS lookup failed"
		if isDNSNotFound(err) {
			detail = "no SPF record found"
		}
		return Result{
			Name:   "SPF",
			Status: StatusNone,
			Detail: detail,
			Err:    fmt.Errorf("spf: lookup %s: %w", domain, err),
		}
	}

	record := findSPFRecord(records)
	if record == "" {
		return Result{Name: "SPF", Status: StatusNone, Detail: "no SPF record found"}
	}

	status, note := spfPolicy(record)
	detail := record
	if note != "" {
		detail = record + " — " + note
	}

	return Result{
		Name:   "SPF",
		Status: status,
		Detail: detail,
	}
}

func findSPFRecord(records []string) string {
	for _, r := range records {
		if strings.HasPrefix(r, "v=spf1") {
			return r
		}
	}
	return ""
}

// spfPolicy classifies the record's enforcement strength. Per RFC 7208 the
// verdict rests on the terminal "all" mechanism, which must be matched as a
// whole term — a substring search would misread tokens such as
// include:spf-all.example.com.
func spfPolicy(record string) (Status, string) {
	var redirect string
	for _, field := range strings.Fields(record) {
		switch {
		case strings.EqualFold(field, "-all"):
			return StatusPass, ""
		case strings.EqualFold(field, "~all"):
			return StatusWarning, "soft fail only, unauthorized senders are marked but delivered"
		case strings.EqualFold(field, "all"), strings.EqualFold(field, "+all"), strings.EqualFold(field, "?all"):
			return StatusFail, "permits any sender"
		case isRedirectModifier(field):
			redirect = field
		}
	}

	if redirect != "" {
		return StatusWarning, "policy delegated via " + redirect + " (not followed)"
	}
	return StatusWarning, "no terminal all mechanism, defaults to neutral"
}

// isRedirectModifier reports whether field is a redirect= modifier naming a
// target domain.
func isRedirectModifier(field string) bool {
	const prefix = "redirect="
	return len(field) > len(prefix) && strings.EqualFold(field[:len(prefix)], prefix)
}
