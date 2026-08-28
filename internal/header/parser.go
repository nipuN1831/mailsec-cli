package header

import (
	"errors"
	"net/mail"
	"strings"
)

// ParseDomain extracts the sender domain from raw email headers.
func ParseDomain(raw string) (string, error) {
	msg, err := mail.ReadMessage(strings.NewReader(raw + "\r\n\r\n"))
	if err != nil {
		return "", errors.New("header: failed to parse email headers")
	}

	from := msg.Header.Get("From")
	if from == "" {
		return "", errors.New("header: no From field found")
	}

	addr, err := mail.ParseAddress(from)
	if err != nil {
		return "", errors.New("header: invalid From address format")
	}

	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", errors.New("header: could not extract domain from From address")
	}

	return parts[1], nil
}

// extractHeaderBlock returns the email header block (stops at blank line separating headers from body).
// Normalizes line endings first to handle mixed EOL variants robustly.
func extractHeaderBlock(raw string) string {
	// Normalize all line endings to LF to handle mixed EOL patterns uniformly.
	// This also ensures extracting the earliest blank-line boundary correctly.
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")

	// Find the header/body boundary (blank line = "\n\n")
	if idx := strings.Index(normalized, "\n\n"); idx >= 0 {
		return normalized[:idx]
	}

	// No blank line found, treat entire input as headers
	return normalized
}

// unfoldHeaders joins RFC 5322 folded header lines (continuations starting with space/tab).
// Only operates on the header block; respects the header/body boundary.
func unfoldHeaders(raw string) string {
	headers := extractHeaderBlock(raw)
	// Headers are already normalized to LF, so only need to handle "\n " and "\n\t"
	unfolded := strings.ReplaceAll(headers, "\n ", " ")
	unfolded = strings.ReplaceAll(unfolded, "\n\t", " ")
	return unfolded
}

// ParseDKIMSelector extracts the selector from a DKIM-Signature header.
// Returns "default" if not found.
func ParseDKIMSelector(raw string) string {
	unfolded := unfoldHeaders(raw)
	for _, line := range strings.Split(unfolded, "\n") {
		// Case-insensitive header name match
		if len(line) < 16 {
			continue
		}
		headerName := line[:15] // "DKIM-Signature:"
		if !strings.EqualFold(headerName, "DKIM-Signature:") {
			continue
		}
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "s=") {
				return strings.TrimPrefix(part, "s=")
			}
		}
	}
	return "default"
}
