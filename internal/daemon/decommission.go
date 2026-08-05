package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

func Decommission(ctx context.Context, store *Store) error {
	cfg, err := store.LoadConfig()
	if err != nil {
		return err
	}
	id, err := store.LoadIdentity()
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	req := protocol.DecommissionRequest{
		At:        at,
		Signature: id.Sign(protocol.DecommissionSigningInput(cfg.HostID, at)),
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	url := strings.TrimRight(cfg.ControlPlane, "/") + "/hosts/" + cfg.HostID + "/decommission"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("control plane rejected decommission: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
