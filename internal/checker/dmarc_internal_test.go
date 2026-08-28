package checker

import "testing"

func TestDMARCPolicyStatus(t *testing.T) {
	cases := []struct {
		policy string
		want   Status
	}{
		{"reject", StatusPass},
		{"quarantine", StatusWarning},
		{"none", StatusFail},
		{"", StatusFail},
	}

	for _, tc := range cases {
		got := dmarcPolicyStatus(tc.policy)
		if got != tc.want {
			t.Errorf("dmarcPolicyStatus(%q) = %s, want %s", tc.policy, got, tc.want)
		}
	}
}
