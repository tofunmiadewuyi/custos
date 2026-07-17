package daemon

import (
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

func entry(fp string, accounts ...string) protocol.AccessEntry {
	return protocol.AccessEntry{Fingerprint: fp, KeyType: "ssh-ed25519", KeyBlob: "AAAA", Accounts: accounts}
}

func TestCacheApplyAndLookup(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := store.LoadCache()
	if err != nil {
		t.Fatal(err)
	}

	if err := cache.ApplySnapshot(protocol.Snapshot{Entries: []protocol.AccessEntry{
		entry("fp-a", "deploy"),
		entry("fp-b", "deploy", "root"),
	}}); err != nil {
		t.Fatal(err)
	}
	if cache.Len() != 2 {
		t.Fatalf("want 2 entries, got %d", cache.Len())
	}
	if _, ok := cache.Lookup("fp-a"); !ok {
		t.Fatal("fp-a should be present")
	}

	// Grant adds, Revoke removes.
	if err := cache.ApplyGrant(protocol.Grant{Entry: entry("fp-c", "deploy")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup("fp-c"); !ok {
		t.Fatal("fp-c should be present after grant")
	}
	if err := cache.ApplyRevoke(protocol.Revoke{Fingerprint: "fp-a"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup("fp-a"); ok {
		t.Fatal("fp-a should be gone after revoke")
	}

	// A snapshot replaces the whole set, not merges.
	if err := cache.ApplySnapshot(protocol.Snapshot{Entries: []protocol.AccessEntry{entry("fp-z", "deploy")}}); err != nil {
		t.Fatal(err)
	}
	if cache.Len() != 1 {
		t.Fatalf("snapshot should replace: want 1, got %d", cache.Len())
	}
	if _, ok := cache.Lookup("fp-b"); ok {
		t.Fatal("fp-b should be gone after replacing snapshot")
	}
}

func TestCachePersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	store, _ := OpenStore(dir)
	cache, _ := store.LoadCache()
	if err := cache.ApplyGrant(protocol.Grant{Entry: entry("fp-a", "deploy")}); err != nil {
		t.Fatal(err)
	}

	// A new store over the same dir must read the persisted entry back.
	store2, _ := OpenStore(dir)
	cache2, err := store2.LoadCache()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := cache2.Lookup("fp-a")
	if !ok {
		t.Fatal("fp-a should persist across reload")
	}
	if len(got.Accounts) != 1 || got.Accounts[0] != "deploy" {
		t.Fatalf("unexpected accounts after reload: %v", got.Accounts)
	}
}
