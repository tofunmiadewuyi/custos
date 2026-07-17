// Package vault seals and opens secrets with envelope encryption: each secret
// is encrypted under its own random data key (AES-256-GCM), and that data key
// is wrapped by a master key held behind a KeyWrapper (a KMS/HSM in
// production). The plaintext master key never appears in this package.
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

// KeyWrapper locks and unlocks per-secret data keys with the master key.
// Production implementations delegate to a KMS/HSM so the master key never
// enters this process; the wrapped form is opaque to the vault.
type KeyWrapper interface {
	Wrap(ctx context.Context, dataKey []byte) (wrapped []byte, err error)
	Unwrap(ctx context.Context, wrapped []byte) (dataKey []byte, err error)
}

// Sealed is the stored form of a secret. None of it is sensitive without the
// master key behind the KeyWrapper.
type Sealed struct {
	Ciphertext []byte
	Nonce      []byte
	WrappedKey []byte
}

// Seal encrypts plaintext under a fresh random data key and returns the sealed
// form. The data key is wrapped by the master key and wiped before returning.
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

// Open unwraps the data key and decrypts the secret. It returns an error if the
// ciphertext has been tampered with (GCM authentication) or the key is wrong.
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
