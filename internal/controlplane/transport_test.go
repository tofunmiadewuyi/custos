package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/hybrid"
)

func TestReadRequestEncrypted(t *testing.T) {
	serverPriv, serverPub, err := hybrid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{EncryptionEnabled: true, HybridPrivateKey: serverPriv}}

	plain, _ := json.Marshal(loginRequest{Email: "a@b.com", Password: "pw"})
	sealed, err := hybrid.Seal(serverPub, plain)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(string(sealed)))

	var got loginRequest
	if err := s.readRequest(req, &got); err != nil {
		t.Fatal(err)
	}
	if got.Email != "a@b.com" || got.Password != "pw" {
		t.Fatalf("decrypted mismatch: %+v", got)
	}
}

func TestReadRequestPlaintextWhenDisabled(t *testing.T) {
	s := &Server{cfg: Config{EncryptionEnabled: false}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"email":"a@b.com","password":"pw"}`))

	var got loginRequest
	if err := s.readRequest(req, &got); err != nil {
		t.Fatal(err)
	}
	if got.Email != "a@b.com" {
		t.Fatalf("got %+v", got)
	}
}

func TestWriteResponseSealsToClient(t *testing.T) {
	clientPriv, clientPub, _ := hybrid.GenerateKeyPair()
	s := &Server{cfg: Config{EncryptionEnabled: true}}

	rec := httptest.NewRecorder()
	s.writeResponse(rec, clientPub, tokenPair{AccessToken: "acc", RefreshToken: "ref"})

	opened, err := hybrid.Open(clientPriv, rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var resp tokenPair
	if err := json.Unmarshal(opened, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken != "acc" || resp.RefreshToken != "ref" {
		t.Fatalf("got %+v", resp)
	}
}

func TestLoginRejectsBadRequest(t *testing.T) {
	s := NewServer(Config{EncryptionEnabled: false}, nil)
	for name, body := range map[string]string{
		"invalid json":   "{bad",
		"missing fields": `{"email":"a@b.com"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
	}
}
