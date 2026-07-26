package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// machineID returns an app-specific hash of the systemd machine-id, so the same
// box is recognizable on re-enroll without shipping the raw id. Empty if the
// machine has no id (non-systemd, some containers) — the guard just won't apply.
func machineID() string {
	raw, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		if raw, err = os.ReadFile("/var/lib/dbus/machine-id"); err != nil {
			return ""
		}
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("custos-host:" + id))
	return hex.EncodeToString(sum[:])
}

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
		MachineID: machineID(),
	})
	if err != nil {
		return err
	}
	// Save the identity first: without it we can't authenticate, and a stray
	// config with no key is worse than no config.
	if err := store.SaveIdentity(kp); err != nil {
		return err
	}
	return store.SaveConfig(Config{
		ControlPlane:     opts.ControlPlane,
		HostID:           resp.HostID,
		SigningPublicKey: resp.SigningPublicKey,
	})
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
