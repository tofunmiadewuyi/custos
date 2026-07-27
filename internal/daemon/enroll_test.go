package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

func TestEnroll(t *testing.T) {
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

	// Second enrollment must be refused.
	if err := Enroll(context.Background(), store, EnrollOptions{ControlPlane: srv.URL, Token: "tok"}); err == nil {
		t.Fatal("expected second enroll to fail")
	}
}
