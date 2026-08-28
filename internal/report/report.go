package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/nipun/mailsec/internal/checker"
)

func Print(w io.Writer, domain string, results []checker.Result) {
	fmt.Fprintf(w, "\nDomain: %s\n\n", domain)
	for _, r := range results {
		icon := statusIcon(r.Status)
		fmt.Fprintf(w, "%-6s %s %-10s %s\n", r.Name, icon, r.Status, r.Detail)
	}
	fmt.Fprintf(w, "\nVerdict: %s\n", verdict(results))
}

func PrintJSON(w io.Writer, domain string, results []checker.Result) error {
	type entry struct {
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	out := struct {
		Domain  string            `json:"domain"`
		Checks  map[string]entry  `json:"checks"`
		Verdict string            `json:"verdict"`
	}{
		Domain:  domain,
		Checks:  make(map[string]entry),
		Verdict: string(verdictStatus(results)),
	}
	for _, r := range results {
		out.Checks[strings.ToLower(r.Name)] = entry{
			Status: string(r.Status),
			Detail: r.Detail,
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func statusIcon(s checker.Status) string {
	switch s {
	case checker.StatusPass:
		return "✓"
	case checker.StatusFail:
		return "✗"
	case checker.StatusWarning:
		return "⚠"
	default:
		return "?"
	}
}

func verdict(results []checker.Result) string {
	switch verdictStatus(results) {
	case checker.StatusPass:
		return "SECURE — all authentication checks passed"
	case checker.StatusWarning:
		return "WEAK — partial enforcement, email may not be fully protected"
	case checker.StatusNone:
		return "UNCONFIGURED — no email authentication found"
	default:
		return "VULNERABLE — authentication checks failed"
	}
}

func verdictStatus(results []checker.Result) checker.Status {
	hasWarning := false
	allNone := true
	for _, r := range results {
		if r.Status == checker.StatusFail {
			return checker.StatusFail
		}
		if r.Status == checker.StatusWarning {
			hasWarning = true
		}
		if r.Status != checker.StatusNone {
			allNone = false
		}
	}
	if allNone {
		return checker.StatusNone
	}
	if hasWarning {
		return checker.StatusWarning
	}
	return checker.StatusPass
}
