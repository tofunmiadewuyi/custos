package daemon

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/hybrid"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

func serveStore(t *testing.T, store *SecretStore) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go ServeSecrets(ln, store, nil)
	t.Cleanup(func() { ln.Close() })
	return sock
}

func TestFetchSetRoundTrip(t *testing.T) {
	kp, _ := hybrid.GenerateKeyPair()
	store := NewSecretStore(kp)
	store.Apply(sealBundle(t, kp, protocol.SecretSet{
		Name: "billing", Version: 1, Values: map[string]string{"DB_URL": "x", "MASTER_KEY": "s3cr3t"},
	}), 1)
	sock := serveStore(t, store)

	values, err := FetchSet(sock, "billing", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if values["MASTER_KEY"] != "s3cr3t" || values["DB_URL"] != "x" {
		t.Fatalf("unexpected values: %v", values)
	}
}

func TestFetchScopedSetForbidden(t *testing.T) {
	kp, _ := hybrid.GenerateKeyPair()
	store := NewSecretStore(kp)
	// as_user "root": the test process is not root, so it must be denied — and
	// off Linux peerUID is unsupported, which also denies. Either way: forbidden.
	store.Apply(sealBundle(t, kp, protocol.SecretSet{
		Name: "scoped", AsUser: "root", Version: 1, Values: map[string]string{"K": "v"},
	}), 1)
	sock := serveStore(t, store)

	if _, err := FetchSet(sock, "scoped", time.Second); err == nil {
		t.Fatal("expected a scoped set for another user to be forbidden")
	}
}
