package checker_test

import (
	"context"
	"github.com/nipun/mailsec/internal/checker"
	"testing"
)

func TestSPFChecker_real_domain(t *testing.T) {
	// google.com has a well-known SPF record
	c := checker.NewSPFChecker()
	result := c.Check(context.Background(), "google.com")

	if result.Status == checker.StatusNone {
		t.Errorf("google.com should have an SPF record")
	}
	if result.Err != nil {
		t.Errorf("unexpected error: %v", result.Err)
	}
	if result.Name != "SPF" {
		t.Errorf("want Name=SPF, got %s", result.Name)
	}
}

func TestSPFChecker_nonexistent_domain(t *testing.T) {
	c := checker.NewSPFChecker()
	result := c.Check(context.Background(), "this-domain-does-not-exist-nipun123.com")

	if result.Status != checker.StatusNone {
		t.Errorf("want StatusNone for nonexistent domain, got %s", result.Status)
	}
	if result.Err == nil {
		t.Error("want an error for nonexistent domain")
	}
}
