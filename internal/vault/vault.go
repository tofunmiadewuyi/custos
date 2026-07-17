// Package vault seals secrets with envelope encryption: a per-secret AES-256-GCM key, wrapped by a master key behind a KeyWrapper.
package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const keySize = 32 // AES-256

// KeyWrapper locks and unlocks per-secret data keys with the master key (a KMS/HSM in production).
type KeyWrapper interface {
	Wrap(ctx context.Context, dataKey []byte) (wrapped []byte, err error)
	Unwrap(ctx context.Context, wrapped []byte) (dataKey []byte, err error)
}

// Sealed is the stored form of a secret; harmless without the master key.
type Sealed struct {
	Ciphertext []byte
	Nonce      []byte
	WrappedKey []byte
}

// Seal encrypts plaintext under a fresh data key, then wraps that key with the master key.
func Seal(ctx context.Context, kw KeyWrapper, plaintext []byte) (Sealed, error) {
	dataKey := make([]byte, keySize)
	if _, err := rand.Read(dataKey); err != nil {
		return Sealed{}, err
	}
	defer wipe(dataKey)

	gcm, err := newGCM(dataKey)
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	wrapped, err := kw.Wrap(ctx, dataKey)
	if err != nil {
		return Sealed{}, fmt.Errorf("wrap data key: %w", err)
	}
	return Sealed{Ciphertext: ciphertext, Nonce: nonce, WrappedKey: wrapped}, nil
}

// Open unwraps the data key and decrypts; errors if the ciphertext was tampered with.
func Open(ctx context.Context, kw KeyWrapper, s Sealed) ([]byte, error) {
	dataKey, err := kw.Unwrap(ctx, s.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("unwrap data key: %w", err)
	}
	defer wipe(dataKey)

	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, s.Nonce, s.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("secret decryption failed")
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
