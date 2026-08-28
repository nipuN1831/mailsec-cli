package report

import (
	"testing"

	"github.com/nipuN1831/mailsec-cli/internal/checker"
)

func TestVerdictStatus(t *testing.T) {
	cases := []struct {
		name     string
		statuses []checker.Status
		want     checker.Status
	}{
		{
			name:     "everything configured and enforcing",
			statuses: []checker.Status{checker.StatusPass, checker.StatusPass, checker.StatusPass},
			want:     checker.StatusPass,
		},
		{
			name:     "one outright failure",
			statuses: []checker.Status{checker.StatusPass, checker.StatusFail, checker.StatusPass},
			want:     checker.StatusFail,
		},
		{
			name:     "failure outweighs a missing record",
			statuses: []checker.Status{checker.StatusNone, checker.StatusFail, checker.StatusWarning},
			want:     checker.StatusFail,
		},
		{
			name:     "nothing configured at all",
			statuses: []checker.Status{checker.StatusNone, checker.StatusNone, checker.StatusNone},
			want:     checker.StatusNone,
		},
		{
			name:     "one missing record among passes",
			statuses: []checker.Status{checker.StatusPass, checker.StatusNone, checker.StatusPass},
			want:     checker.StatusWarning,
		},
		{
			name:     "one weak policy among passes",
			statuses: []checker.Status{checker.StatusPass, checker.StatusWarning, checker.StatusPass},
			want:     checker.StatusWarning,
		},
		{
			name:     "mixed missing and weak",
			statuses: []checker.Status{checker.StatusNone, checker.StatusWarning, checker.StatusPass},
			want:     checker.StatusWarning,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verdictStatus(resultsWith(tc.statuses))
			if got != tc.want {
				t.Errorf("verdictStatus(%v) = %s, want %s", tc.statuses, got, tc.want)
			}
		})
	}
}

func resultsWith(statuses []checker.Status) []checker.Result {
	results := make([]checker.Result, len(statuses))
	for i, s := range statuses {
		results[i] = checker.Result{Name: "check", Status: s}
	}
	return results
}
