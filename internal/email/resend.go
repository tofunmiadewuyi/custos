package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const resendEndpoint = "https://api.resend.com/emails"

type resendSender struct {
	apiKey string
	from   string
	client *http.Client
}

func newResend(apiKey, from string) *resendSender {
	return &resendSender{apiKey: apiKey, from: from, client: &http.Client{Timeout: 15 * time.Second}}
}

func (r *resendSender) Send(ctx context.Context, msg Message) error {
	body, err := json.Marshal(map[string]any{
		"from":    r.from,
		"to":      []string{msg.To},
		"subject": msg.Subject,
		"html":    msg.HTML,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resendEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("resend: %s: %s", resp.Status, b)
	}
	return nil
}
