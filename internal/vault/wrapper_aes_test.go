package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
)

func TestNewAESWrapperRejectsBadKey(t *testing.T) {
	if _, err := NewAESWrapper(make([]byte, 16)); err == nil {
		t.Fatal("expected error for non-32-byte master key")
	}
}

func TestAESWrapperRoundTrip(t *testing.T) {
	master := make([]byte, keySize)
	rand.Read(master)
	w, err := NewAESWrapper(master)
	if err != nil {
		t.Fatal(err)
	}
	dataKey := make([]byte, keySize)
	rand.Read(dataKey)

	wrapped, err := w.Wrap(context.Background(), dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, dataKey) {
		t.Fatal("data key leaked into wrapped output")
	}
	got, err := w.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dataKey) {
		t.Fatal("unwrap did not recover the data key")
	}
}

func TestAESWrapperUnwrapRejectsBadInput(t *testing.T) {
	master := make([]byte, keySize)
	rand.Read(master)
	w, _ := NewAESWrapper(master)

	if _, err := w.Unwrap(context.Background(), []byte("short")); err == nil {
		t.Fatal("expected error for too-short wrapped key")
	}
	wrapped, _ := w.Wrap(context.Background(), make([]byte, keySize))
	wrapped[len(wrapped)-1] ^= 0xff
	if _, err := w.Unwrap(context.Background(), wrapped); err == nil {
		t.Fatal("expected error for tampered wrapped key")
	}
}
