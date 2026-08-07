package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// seedMachineID points machine-id discovery at a temp file so tests run anywhere
func seedMachineID(t *testing.T) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "machine-id")
	if err := os.WriteFile(p, []byte("test-machine-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := machineIDSources
	machineIDSources = []string{p}
	t.Cleanup(func() { machineIDSources = orig })
}

func TestEnroll(t *testing.T) {
	seedMachineID(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/enroll" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req protocol.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Token != "tok" || req.PublicKey == "" || req.EncryptionKey == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(protocol.EnrollResponse{HostID: "host-abc"})
	}))
	defer srv.Close()

	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = Enroll(context.Background(), store, EnrollOptions{
		ControlPlane: srv.URL, Token: "tok", Hostname: "staging-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !store.Enrolled() {
		t.Fatal("store should report enrolled")
	}
	cfg, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HostID != "host-abc" || cfg.ControlPlane != srv.URL {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if _, err := store.LoadIdentity(); err != nil {
		t.Fatalf("identity should load: %v", err)
	}
	if _, err := store.LoadEncryptionKey(); err != nil {
		t.Fatalf("encryption key should load: %v", err)
	}

	// Re-enrollment re-registers instead of hard-failing (revoke recovery).
	if err := Enroll(context.Background(), store, EnrollOptions{ControlPlane: srv.URL, Token: "tok"}); err != nil {
		t.Fatalf("re-enroll should succeed: %v", err)
	}
}
