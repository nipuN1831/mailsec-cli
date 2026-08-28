package checker_test

import (
	"context"
	"testing"

	"github.com/nipun/mailsec/internal/checker"
)

func TestDMARCChecker_real_domain(t *testing.T) {
	c := checker.NewDMARCChecker()
	result := c.Check(context.Background(), "google.com")

	if result.Name != "DMARC" {
		t.Errorf("want Name=DMARC, got %s", result.Name)
	}
	if result.Err != nil && result.Status != checker.StatusNone {
		t.Errorf("unexpected error: %v", result.Err)
	}
}

func TestDMARCChecker_nonexistent_domain(t *testing.T) {
	c := checker.NewDMARCChecker()
	result := c.Check(context.Background(), "this-domain-does-not-exist-nipun123.com")

	if result.Status != checker.StatusNone {
		t.Errorf("want StatusNone, got %s", result.Status)
	}
}
