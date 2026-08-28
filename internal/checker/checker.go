package checker

import "context"

type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusNone    Status = "none"
	StatusWarning Status = "warning"
)

type Result struct {
	Name   string
	Status Status
	Detail string
	Err    error
}

type Checker interface {
	Check(ctx context.Context, domain string) Result
}

// RunAll runs all checkers concurrently and returns results in order.
func RunAll(ctx context.Context, checkers []Checker, domain string) []Result {
	results := make([]Result, len(checkers))
	done := make(chan struct {
		index  int
		result Result
	}, len(checkers))

	for i, c := range checkers {
		go func(index int, ch Checker) {
			done <- struct {
				index  int
				result Result
			}{index, ch.Check(ctx, domain)}
		}(i, c)
	}

	for range checkers {
		r := <-done
		results[r.index] = r.result
	}
	return results
}
