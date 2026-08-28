package checker_test

import (
	"context"
	"github.com/nipuN1831/mailsec/internal/checker"
	"testing"
	"time"
)

type stubChecker struct {
	result checker.Result
}

func (s stubChecker) Check(_ context.Context, _ string) checker.Result {
	return s.result
}

func TestRunAll_collects_all_results(t *testing.T) {
	checkers := []checker.Checker{
		stubChecker{checker.Result{Name: "spf", Status: checker.StatusPass}},
		stubChecker{checker.Result{Name: "dkim", Status: checker.StatusFail}},
		stubChecker{checker.Result{Name: "dmarc", Status: checker.StatusNone}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	results := checker.RunAll(ctx, checkers, "example.com")

	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}
	if results[0].Name != "spf" {
		t.Errorf("want results[0].Name=spf, got %s", results[0].Name)
	}
	if results[1].Status != checker.StatusFail {
		t.Errorf("want results[1].Status=fail, got %s", results[1].Status)
	}
}
