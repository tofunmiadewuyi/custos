package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// EnrollOptions are the inputs to a one-time enrollment.
type EnrollOptions struct {
	ControlPlane string
	Token        string
	Hostname     string
}

// Enroll registers this host with the control plane: it generates the identity
// keypair, exchanges the admin token for a host ID, and persists both. The
// private key never leaves the machine — only its public half is sent.
func Enroll(ctx context.Context, store *Store, opts EnrollOptions) error {
	if store.Enrolled() {
		return errors.New("already enrolled")
	}
	kp, err := identity.GenerateKeyPair()
	if err != nil {
		return err
	}
	resp, err := postEnroll(ctx, opts.ControlPlane, protocol.EnrollRequest{
		Token:     opts.Token,
		Hostname:  opts.Hostname,
		PublicKey: kp.PublicKey(),
	})
	if err != nil {
		return err
	}
	// Save the identity first: without it we can't authenticate, and a stray
	// config with no key is worse than no config.
	if err := store.SaveIdentity(kp); err != nil {
		return err
	}
	return store.SaveConfig(Config{ControlPlane: opts.ControlPlane, HostID: resp.HostID})
}

func postEnroll(ctx context.Context, baseURL string, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	url := strings.TrimRight(baseURL, "/") + "/enroll"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return out, fmt.Errorf("enroll rejected: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}
