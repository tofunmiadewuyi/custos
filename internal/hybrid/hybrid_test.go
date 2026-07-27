package hybrid

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("the launch codes")

	sealed, err := Seal(kp.Public(), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("plaintext leaked into sealed message")
	}

	got, err := kp.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	kp, _ := GenerateKeyPair()
	wrong, _ := GenerateKeyPair()

	sealed, err := Seal(kp.Public(), []byte("the launch codes"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Open(sealed); err == nil {
		t.Fatal("expected decryption to fail with the wrong private key")
	}
}

func TestOpenRejectsTamperedMessage(t *testing.T) {
	kp, _ := GenerateKeyPair()
	sealed, err := Seal(kp.Public(), []byte("the launch codes"))
	if err != nil {
		t.Fatal(err)
	}

	sealed[len(sealed)-1] ^= 0xff
	if _, err := kp.Open(sealed); err == nil {
		t.Fatal("expected decryption to fail on a tampered message")
	}
}
