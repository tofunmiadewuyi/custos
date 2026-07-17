package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
)

func newWrapper(t *testing.T) *AESWrapper {
	t.Helper()
	master := make([]byte, keySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	kw, err := NewAESWrapper(master)
	if err != nil {
		t.Fatal(err)
	}
	return kw
}

func TestSealOpenRoundTrip(t *testing.T) {
	kw := newWrapper(t)
	plaintext := []byte("hunter2")

	sealed, err := Seal(context.Background(), kw, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Ciphertext, plaintext) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	got, err := Open(context.Background(), kw, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	kw := newWrapper(t)
	sealed, err := Seal(context.Background(), kw, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}

	sealed.Ciphertext[0] ^= 0xff
	if _, err := Open(context.Background(), kw, sealed); err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext")
	}
}
