// Package email sends transactional email through a pluggable provider, so the
// rest of the app depends only on Sender — never on a specific service.
package email

import "context"

type Message struct {
	To      string
	Subject string
	HTML    string
}

type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// New returns a Resend-backed sender, or a log-only sender when no API key is
// configured (dev) — so email flows work without a provider wired up.
func New(apiKey, from string) Sender {
	if apiKey == "" {
		return logSender{}
	}
	return newResend(apiKey, from)
}
