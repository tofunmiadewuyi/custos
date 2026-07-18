package email

import (
	"context"
	"log/slog"
)

// logSender logs messages instead of sending them, so invite/reset flows are
// testable without a provider (the link shows up in the server logs).
type logSender struct{}

func (logSender) Send(_ context.Context, msg Message) error {
	slog.Info("email not sent (no provider configured)", "to", msg.To, "subject", msg.Subject, "body", msg.HTML)
	return nil
}
