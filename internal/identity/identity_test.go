package identity

import "testing"

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}

	sig := kp.Sign(challenge)
	if err := Verify(kp.PublicKey(), challenge, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyRejectsWrongChallenge(t *testing.T) {
	kp, _ := GenerateKeyPair()
	challenge, _ := NewChallenge()
	other, _ := NewChallenge()

	sig := kp.Sign(challenge)
	if err := Verify(kp.PublicKey(), other, sig); err == nil {
		t.Fatal("expected verification to fail for a different challenge")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kp, _ := GenerateKeyPair()
	attacker, _ := GenerateKeyPair()
	challenge, _ := NewChallenge()

	sig := kp.Sign(challenge)
	if err := Verify(attacker.PublicKey(), challenge, sig); err == nil {
		t.Fatal("expected verification to fail against a different public key")
	}
}

func TestLoadKeyPairRestoresSigner(t *testing.T) {
	kp, _ := GenerateKeyPair()
	loaded, err := LoadKeyPair(kp.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PublicKey() != kp.PublicKey() {
		t.Fatal("restored keypair has a different public key")
	}

	challenge, _ := NewChallenge()
	sig := loaded.Sign(challenge)
	if err := Verify(kp.PublicKey(), challenge, sig); err != nil {
		t.Fatalf("signature from restored key rejected: %v", err)
	}
}
