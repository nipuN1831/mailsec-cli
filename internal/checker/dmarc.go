package checker

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type DMARCChecker struct {
	resolver *net.Resolver
}

func NewDMARCChecker() *DMARCChecker {
	return &DMARCChecker{resolver: net.DefaultResolver}
}

func (d *DMARCChecker) Check(ctx context.Context, domain string) Result {
	host := "_dmarc." + domain
	records, err := d.resolver.LookupTXT(ctx, host)
	if err != nil {
		return Result{
			Name:   "DMARC",
			Status: StatusNone,
			Detail: "no DMARC record found",
			Err:    fmt.Errorf("dmarc: lookup %s: %w", host, err),
		}
	}

	record := findDMARCRecord(records)
	if record == "" {
		return Result{Name: "DMARC", Status: StatusNone, Detail: "no DMARC record found"}
	}

	policy := dmarcTag(record, "p")
	pct := dmarcPct(record)
	rua := dmarcTag(record, "rua")

	detail := fmt.Sprintf("policy=%s pct=%d", policy, pct)
	if rua != "" {
		detail += fmt.Sprintf(" rua=%s", rua)
	}

	return Result{
		Name:   "DMARC",
		Status: dmarcPolicyStatus(policy),
		Detail: detail,
	}
}

func findDMARCRecord(records []string) string {
	for _, r := range records {
		if strings.HasPrefix(r, "v=DMARC1") {
			return r
		}
	}
	return ""
}

func dmarcTag(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, tag+"=") {
			return strings.TrimPrefix(part, tag+"=")
		}
	}
	return ""
}

func dmarcPct(record string) int {
	val := dmarcTag(record, "pct")
	if val == "" {
		return 100
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 100
	}
	return n
}

func dmarcPolicyStatus(policy string) Status {
	switch policy {
	case "reject":
		return StatusPass
	case "quarantine":
		return StatusWarning
	default:
		return StatusFail // "none" or missing means no enforcement
	}
}
