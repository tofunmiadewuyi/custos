package hybrid

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("the launch codes")

	sealed, err := Seal(pub, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("plaintext leaked into sealed message")
	}

	got, err := Open(priv, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	wrongPriv, _, _ := GenerateKeyPair()

	sealed, err := Seal(pub, []byte("the launch codes"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(wrongPriv, sealed); err == nil {
		t.Fatal("expected decryption to fail with the wrong private key")
	}
}

func TestOpenRejectsTamperedMessage(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sealed, err := Seal(pub, []byte("the launch codes"))
	if err != nil {
		t.Fatal(err)
	}

	sealed[len(sealed)-1] ^= 0xff
	if _, err := Open(priv, sealed); err == nil {
		t.Fatal("expected decryption to fail on a tampered message")
	}
}
