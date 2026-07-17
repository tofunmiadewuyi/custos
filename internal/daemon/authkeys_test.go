package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
	"github.com/tofunmiadewuyi/custos/internal/sshkey"
)

// a real ed25519 blob so Fingerprint agrees between seeding and lookup.
const testBlob = "AAAAC3NzaC1lZDI1NTE5AAAAIF79/jbso5ZK5Lvu2nbla+Ba7nMgnFIiTRc+G1hohsYO"

func seededCache(t *testing.T, accounts ...string) (*Store, *Cache) {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := store.LoadCache()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := sshkey.Fingerprint(testBlob)
	if err != nil {
		t.Fatal(err)
	}
	err = cache.ApplyGrant(protocol.Grant{Entry: protocol.AccessEntry{
		KeyType: "ssh-ed25519", KeyBlob: testBlob, Fingerprint: fp, Accounts: accounts,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return store, cache
}

func startServer(t *testing.T, cache *Cache) string {
	t.Helper()
	// Unix socket paths are length-limited (~104 chars on macOS), so keep the
	// dir short rather than using the long t.TempDir() path.
	dir, err := os.MkdirTemp("/tmp", "cst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeAuth(ln, cache, nil)
	return sock
}

func TestAuthorizedKeyOverSocket(t *testing.T) {
	store, cache := seededCache(t, "deploy")
	sock := startServer(t, cache)

	line, err := AuthorizedKey(sock, store, "ssh-ed25519", testBlob, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	want := "ssh-ed25519 " + testBlob
	if line != want {
		t.Fatalf("got %q, want %q", line, want)
	}
}

func TestAuthorizedKeyDeniesWrongAccount(t *testing.T) {
	store, cache := seededCache(t, "deploy")
	sock := startServer(t, cache)

	line, err := AuthorizedKey(sock, store, "ssh-ed25519", testBlob, "root")
	if err != nil {
		t.Fatal(err)
	}
	if line != "" {
		t.Fatalf("expected denial for wrong account, got %q", line)
	}
}

func TestAuthorizedKeyFallsBackToDisk(t *testing.T) {
	store, _ := seededCache(t, "deploy")
	// No server running: point at a dead socket path and confirm the on-disk
	// cache still authorizes the login.
	line, err := AuthorizedKey("/nonexistent/custosd.sock", store, "ssh-ed25519", testBlob, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	want := "ssh-ed25519 " + testBlob
	if line != want {
		t.Fatalf("fallback got %q, want %q", line, want)
	}
}
