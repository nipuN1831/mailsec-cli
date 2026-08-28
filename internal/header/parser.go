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

// ParseDKIMSelector extracts the selector from a DKIM-Signature header.
// Returns "default" if not found.
func ParseDKIMSelector(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "DKIM-Signature:") {
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
