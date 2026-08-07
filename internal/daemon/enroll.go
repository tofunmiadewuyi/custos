package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/hybrid"
	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// stable, wipe-surviving id sources, first non-empty wins; app containers have none
var machineIDSources = []string{
	"/etc/machine-id",
	"/var/lib/dbus/machine-id",
	"/sys/class/dmi/id/product_uuid",
}

// machineID hashes the first available machine identifier; empty means not a real host
func machineID() string {
	var raw string
	for _, src := range machineIDSources {
		b, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		if raw = strings.TrimSpace(string(b)); raw != "" {
			break
		}
	}
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("custos-host:" + raw))
	return hex.EncodeToString(sum[:])
}

// EnrollOptions are the inputs to a one-time enrollment.
type EnrollOptions struct {
	ControlPlane string
	Token        string
	Hostname     string
}

// Enroll registers this host with the control plane: it generates a fresh
// identity keypair, exchanges the admin token for a host ID, and persists both.
// The private key never leaves the machine. Re-enrollment is allowed: an
// already-enrolled box just re-registers (revoke frees the machine server-side,
// so this is how a revoked host recovers). New keys are written only after the
// control plane accepts, so a still-active box that re-enrolls gets a 409 and
// keeps its working identity. The control plane is the authority on duplicates.
func Enroll(ctx context.Context, store *Store, opts EnrollOptions) error {
	mID := machineID()
	if mID == "" {
		return fmt.Errorf("no stable machine id (%s); custos targets machines with their own sshd, not app containers", strings.Join(machineIDSources, ", "))
	}
	kp, err := identity.GenerateKeyPair()
	if err != nil {
		return err
	}
	encKP, err := hybrid.GenerateKeyPair()
	if err != nil {
		return err
	}
	// Carry the prior host id (if any) so the server can dedup re-enrolls even
	// when machine_id is unavailable. Best-effort: a missing config just omits it.
	var priorHostID string
	if cfg, err := store.LoadConfig(); err == nil {
		priorHostID = cfg.HostID
	}
	resp, err := postEnroll(ctx, opts.ControlPlane, protocol.EnrollRequest{
		Token:         opts.Token,
		Hostname:      opts.Hostname,
		PublicKey:     kp.PublicKey(),
		EncryptionKey: encKP.PublicKey(),
		MachineID:     mID,
		PriorHostID:   priorHostID,
	})
	if err != nil {
		return err
	}
	// Save the keys first: without them we can't authenticate or decrypt, and a
	// stray config with no keys is worse than no config.
	if err := store.SaveIdentity(kp); err != nil {
		return err
	}
	if err := store.SaveEncryptionKey(encKP); err != nil {
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
