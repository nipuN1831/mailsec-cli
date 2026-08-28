package checker_test

import (
	"context"
	"testing"
	"github.com/nipun/mailsec/internal/checker"
)

func TestDKIMChecker_known_selector(t *testing.T) {
	// google.com uses selector "20230601"
	c := checker.NewDKIMChecker("20230601")
	result := c.Check(context.Background(), "google.com")

	// May be none if selector rotated — just check it doesn't crash
	if result.Name != "DKIM" {
		t.Errorf("want Name=DKIM, got %s", result.Name)
	}
}

func TestDKIMChecker_missing_selector(t *testing.T) {
	c := checker.NewDKIMChecker("nonexistent-selector-xyz")
	result := c.Check(context.Background(), "google.com")

	if result.Status != checker.StatusNone {
		t.Errorf("want StatusNone for missing selector, got %s", result.Status)
	}
}

func TestDKIMChecker_default_selector_name(t *testing.T) {
	c := checker.NewDKIMChecker("")
	if c.Selector != "default" {
		t.Errorf("want Selector=default when empty, got %s", c.Selector)
	}
}
