package checker

import (
	"context"
	"net"
	"testing"
)

// stubLookup builds a canned lookupTXT so checker tests stay deterministic and
// offline.
func stubLookup(records []string, err error) lookupFunc {
	return func(context.Context, string) ([]string, error) {
		return records, err
	}
}

func TestIsDNSNotFound(t *testing.T) {
	if !isDNSNotFound(&net.DNSError{IsNotFound: true}) {
		t.Error("want true for an NXDOMAIN error")
	}
	if isDNSNotFound(&net.DNSError{IsTimeout: true}) {
		t.Error("want false for a timeout")
	}
	if isDNSNotFound(context.DeadlineExceeded) {
		t.Error("want false for a non-DNS error")
	}
}
