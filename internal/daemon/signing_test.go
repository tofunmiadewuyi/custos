package daemon

import (
	"encoding/json"
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

func TestDispatchSnapshotSigning(t *testing.T) {
	cp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.GenerateKeyPair()
	const hostID = "host-xyz"

	store, _ := OpenStore(t.TempDir())
	cache, _ := store.LoadCache()
	c := NewClient(Config{HostID: hostID, SigningPublicKey: cp.PublicKey()}, id, cache, "v0.0.0", t.TempDir())
	send := make(chan protocol.Envelope, 1)

	signed := func(signer *identity.KeyPair, sigHostID string, seq uint64, fps ...string) protocol.Envelope {
		es := make([]protocol.AccessEntry, len(fps))
		for i, fp := range fps {
			es[i] = entry(fp, "deploy")
		}
		data, _ := json.Marshal(protocol.Snapshot{Entries: es})
		sig := signer.Sign(protocol.SnapshotSigningInput(sigHostID, seq, data))
		return protocol.Envelope{Type: protocol.TypeSnapshot, Data: data, Seq: seq, Sig: sig}
	}

	// Valid signed snapshot applies.
	if err := c.dispatch(signed(cp, hostID, 1, "fp-a"), send); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup("fp-a"); !ok || cache.Seq() != 1 {
		t.Fatalf("valid snapshot not applied: seq=%d", cache.Seq())
	}

	// Tampered data (old sig) is dropped, cache unchanged.
	bad := signed(cp, hostID, 2, "fp-a")
	tampered, _ := json.Marshal(protocol.Snapshot{Entries: []protocol.AccessEntry{entry("fp-evil", "deploy")}})
	bad.Data = tampered
	if err := c.dispatch(bad, send); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup("fp-evil"); ok || cache.Seq() != 1 {
		t.Fatal("tampered snapshot was applied")
	}

	// Wrong signing key is dropped.
	attacker, _ := identity.GenerateKeyPair()
	if err := c.dispatch(signed(attacker, hostID, 2, "fp-b"), send); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup("fp-b"); ok {
		t.Fatal("snapshot signed by wrong key was applied")
	}

	// Signature bound to a different host is dropped.
	if err := c.dispatch(signed(cp, "other-host", 2, "fp-c"), send); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup("fp-c"); ok {
		t.Fatal("snapshot signed for another host was applied")
	}

	// Stale seq (<= current) is dropped even when validly signed.
	if err := c.dispatch(signed(cp, hostID, 1, "fp-d"), send); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup("fp-d"); ok {
		t.Fatal("replayed snapshot was applied")
	}

	// A newer seq applies and replaces the set.
	if err := c.dispatch(signed(cp, hostID, 2, "fp-e"), send); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.Lookup("fp-e"); !ok || cache.Seq() != 2 {
		t.Fatalf("newer snapshot not applied: seq=%d", cache.Seq())
	}
	if _, ok := cache.Lookup("fp-a"); ok {
		t.Fatal("snapshot should replace, not merge")
	}
}
