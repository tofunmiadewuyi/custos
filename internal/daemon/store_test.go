package daemon

import (
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/identity"
)

func TestConfigRoundTrip(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := Config{ControlPlane: "https://cp.example.com", HostID: "host-123"}
	if err := s.SaveConfig(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("config round trip: got %+v want %+v", got, want)
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s.Enrolled() {
		t.Fatal("fresh store should not report enrolled")
	}

	kp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveIdentity(kp); err != nil {
		t.Fatal(err)
	}
	if !s.Enrolled() {
		t.Fatal("store should report enrolled after saving identity")
	}

	loaded, err := s.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PublicKey() != kp.PublicKey() {
		t.Fatal("loaded identity has a different public key")
	}
}
