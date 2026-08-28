package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type SPFChecker struct {
	resolver *net.Resolver
}

func NewSPFChecker() *SPFChecker {
	return &SPFChecker{resolver: net.DefaultResolver}
}

func (s *SPFChecker) Check(ctx context.Context, domain string) Result {
	records, err := s.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return Result{
			Name:   "SPF",
			Status: StatusNone,
			Detail: "DNS lookup failed",
			Err:    fmt.Errorf("spf: lookup %s: %w", domain, err),
		}
	}

	record := findSPFRecord(records)
	if record == "" {
		return Result{Name: "SPF", Status: StatusNone, Detail: "no SPF record found"}
	}

	return Result{
		Name:   "SPF",
		Status: spfPolicyStatus(record),
		Detail: record,
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

func spfPolicyStatus(record string) Status {
	switch {
	case strings.Contains(record, "-all"):
		return StatusPass // strict — rejects unauthorized senders
	case strings.Contains(record, "~all"):
		return StatusWarning // soft fail — marks but doesn't reject
	default:
		return StatusFail // +all or ?all — allows everything, insecure
	}
}
