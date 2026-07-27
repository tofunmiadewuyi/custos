package daemon

import (
	"encoding/json"
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/hybrid"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// sealBundle seals a whole cleartext bundle to the host key, as the control plane would.
func sealBundle(t *testing.T, kp *hybrid.KeyPair, sets ...protocol.SecretSet) protocol.SealedSecretSets {
	t.Helper()
	data, _ := json.Marshal(protocol.SecretSets{Sets: sets})
	sealed, err := hybrid.Seal(kp.Public(), data)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.SealedSecretSets{Sealed: sealed}
}

func TestSecretStoreApplyGet(t *testing.T) {
	kp, err := hybrid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store := NewSecretStore(kp)

	bundle := sealBundle(t, kp, protocol.SecretSet{
		Name: "billing", AsUser: "billing-svc", Version: 1,
		Values: map[string]string{"DB_URL": "postgres://x", "MASTER_KEY": "s3cr3t"},
	})
	if err := store.Apply(bundle, 1); err != nil {
		t.Fatal(err)
	}
	if store.Seq() != 1 {
		t.Fatalf("seq = %d, want 1", store.Seq())
	}

	values, asUser, ok := store.Get("billing")
	if !ok {
		t.Fatal("set not found")
	}
	if asUser != "billing-svc" || values["MASTER_KEY"] != "s3cr3t" || values["DB_URL"] != "postgres://x" {
		t.Fatalf("unexpected: as_user=%q values=%v", asUser, values)
	}

	// A returned copy must not mutate the store.
	values["MASTER_KEY"] = "tampered"
	again, _, _ := store.Get("billing")
	if again["MASTER_KEY"] != "s3cr3t" {
		t.Fatal("Get must return a copy, not the stored map")
	}

	if _, _, ok := store.Get("missing"); ok {
		t.Fatal("missing set should not be found")
	}
}

func TestSecretStoreApplyReplaces(t *testing.T) {
	kp, _ := hybrid.GenerateKeyPair()
	store := NewSecretStore(kp)

	store.Apply(sealBundle(t, kp, protocol.SecretSet{Name: "old", Version: 1, Values: map[string]string{"K": "1"}}), 1)
	store.Apply(sealBundle(t, kp, protocol.SecretSet{Name: "new", Version: 1, Values: map[string]string{"K": "2"}}), 2)

	if _, _, ok := store.Get("old"); ok {
		t.Fatal("Apply should replace, not merge")
	}
	if v, _, _ := store.Get("new"); v["K"] != "2" {
		t.Fatal("new set missing after replace")
	}
}

func TestSecretStoreNoKey(t *testing.T) {
	store := NewSecretStore(nil)
	if err := store.Apply(protocol.SealedSecretSets{}, 1); err == nil {
		t.Fatal("Apply with no key should error")
	}
}
