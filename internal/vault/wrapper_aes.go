package vault

import (
	"context"
	"crypto/rand"
	"errors"
)

// AESWrapper locks data keys with a master key held in process memory, using
// AES-256-GCM. It suits development and deployments that manage the master key
// themselves. Production should prefer a KMS/HSM-backed KeyWrapper so the
// master key never resides in this process.
type AESWrapper struct {
	master []byte
}

func NewAESWrapper(masterKey []byte) (*AESWrapper, error) {
	if len(masterKey) != keySize {
		return nil, errors.New("master key must be 32 bytes")
	}
	return &AESWrapper{master: masterKey}, nil
}

func (w *AESWrapper) Wrap(_ context.Context, dataKey []byte) ([]byte, error) {
	gcm, err := newGCM(w.master)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Prepend the nonce so Unwrap can recover it.
	return gcm.Seal(nonce, nonce, dataKey, nil), nil
}

func (w *AESWrapper) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	gcm, err := newGCM(w.master)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("wrapped key too short")
	}
	nonce, ciphertext := wrapped[:ns], wrapped[ns:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
