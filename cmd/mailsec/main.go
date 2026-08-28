// cmd/mailsec/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nipuN1831/mailsec/internal/checker"
	"github.com/nipuN1831/mailsec/internal/header"
	"github.com/nipuN1831/mailsec/internal/report"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// isTerminal reports whether r is an interactive terminal, in which case
// reading it would block forever waiting for input nobody is going to type.
// Test doubles are not *os.File and correctly fall through to reading.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("mailsec", flag.ContinueOnError)
	domain := flags.String("domain", "", "domain to check (e.g. example.com)")
	selector := flags.String("selector", "default", "DKIM selector to look up")
	asJSON := flags.Bool("json", false, "output results as JSON")
	timeout := flags.Duration("timeout", 5*time.Second, "DNS lookup timeout")

	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}

	// Determine domain and selector from flags or stdin headers
	resolvedDomain := *domain
	resolvedSelector := *selector

	if resolvedDomain == "" {
		if isTerminal(stdin) {
			return fmt.Errorf("provide --domain or pipe raw email headers via stdin")
		}

		raw, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		resolvedDomain, err = header.ParseDomain(string(raw))
		if err != nil {
			return fmt.Errorf("parsing headers: %w", err)
		}
		resolvedSelector = header.ParseDKIMSelector(string(raw))
	}

	if resolvedDomain == "" {
		return fmt.Errorf("provide --domain or pipe raw email headers via stdin")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	checkers := []checker.Checker{
		checker.NewSPFChecker(),
		checker.NewDKIMChecker(resolvedSelector),
		checker.NewDMARCChecker(),
	}

	results := checker.RunAll(ctx, checkers, resolvedDomain)

	if *asJSON {
		return report.PrintJSON(stdout, resolvedDomain, results)
	}
	report.Print(stdout, resolvedDomain, results)
	return nil
}
