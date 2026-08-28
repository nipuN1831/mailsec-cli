package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/nipuN1831/mailsec/internal/checker"
)

// errIndent aligns the cause line under the Detail column of the check line.
const errIndent = 20

func Print(w io.Writer, domain string, results []checker.Result) {
	fmt.Fprintf(w, "\nDomain: %s\n\n", domain)
	for _, r := range results {
		icon := statusIcon(r.Status)
		fmt.Fprintf(w, "%-6s %s %-10s %s\n", r.Name, icon, r.Status, r.Detail)
		if r.Err != nil {
			fmt.Fprintf(w, "%*scause: %v\n", errIndent, "", r.Err)
		}
	}
	fmt.Fprintf(w, "\nVerdict: %s\n", verdict(results))
}

func PrintJSON(w io.Writer, domain string, results []checker.Result) error {
	type entry struct {
		Status string `json:"status"`
		Detail string `json:"detail"`
		Error  string `json:"error,omitempty"`
	}
	out := struct {
		Domain  string           `json:"domain"`
		Checks  map[string]entry `json:"checks"`
		Verdict string           `json:"verdict"`
	}{
		Domain:  domain,
		Checks:  make(map[string]entry),
		Verdict: string(verdictStatus(results)),
	}
	for _, r := range results {
		e := entry{
			Status: string(r.Status),
			Detail: r.Detail,
		}
		if r.Err != nil {
			e.Error = r.Err.Error()
		}
		out.Checks[strings.ToLower(r.Name)] = e
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

// verdictStatus reduces the per-check statuses to one overall verdict. A single
// missing record is enough to withhold a passing verdict: a domain with SPF but
// no DMARC is exactly the gap this tool exists to surface.
func verdictStatus(results []checker.Result) checker.Status {
	allNone := true
	allPass := true
	for _, r := range results {
		if r.Status == checker.StatusFail {
			return checker.StatusFail
		}
		if r.Status != checker.StatusNone {
			allNone = false
		}
		if r.Status != checker.StatusPass {
			allPass = false
		}
	}

	switch {
	case allNone:
		return checker.StatusNone
	case allPass:
		return checker.StatusPass
	default:
		return checker.StatusWarning
	}
}
