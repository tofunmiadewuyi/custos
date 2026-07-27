// Package hybrid does ECDH/X25519 hybrid public-key encryption for API<->frontend payloads (ephemeral key agreement + AES-256-GCM).
package hybrid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	keySize  = 32
	hkdfInfo = "custos-hybrid:v1"
)

// KeyPair is a persisted X25519 keypair a holder reuses to open sealed messages.
type KeyPair struct{ priv *ecdh.PrivateKey }

// GenerateKeyPair returns a fresh X25519 keypair.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{priv: priv}, nil
}

// NewKeyPair wraps a raw X25519 private key.
func NewKeyPair(privateKey []byte) (*KeyPair, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &KeyPair{priv: priv}, nil
}

// LoadKeyPair restores a keypair from a base64 private key persisted on disk.
func LoadKeyPair(privateKey string) (*KeyPair, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	return NewKeyPair(raw)
}

func (k *KeyPair) PublicKey() string  { return base64.StdEncoding.EncodeToString(k.priv.PublicKey().Bytes()) }
func (k *KeyPair) PrivateKey() string { return base64.StdEncoding.EncodeToString(k.priv.Bytes()) }

// Public/Private return the raw key bytes for the free Seal/Open functions.
func (k *KeyPair) Public() []byte  { return k.priv.PublicKey().Bytes() }
func (k *KeyPair) Private() []byte { return k.priv.Bytes() }

// Open decrypts a message sealed to this keypair.
func (k *KeyPair) Open(sealed []byte) ([]byte, error) { return Open(k.priv.Bytes(), sealed) }

// Seal encrypts plaintext to recipientPublic, returning a self-contained message: ephemeralPub(32) ‖ nonce(12) ‖ ciphertext.
func Seal(recipientPublic, plaintext []byte) ([]byte, error) {
	curve := ecdh.X25519()
	recipient, err := curve.NewPublicKey(recipientPublic)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	ephemeralPub := ephemeral.PublicKey().Bytes()

	gcm, err := deriveGCM(shared, ephemeralPub, recipientPublic)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(ephemeralPub)+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, ephemeralPub...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, nil), nil
}

// Open decrypts a message sealed to the keypair identified by recipientPrivate.
func Open(recipientPrivate, sealed []byte) ([]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(recipientPrivate)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient private key: %w", err)
	}
	if len(sealed) < keySize {
		return nil, errors.New("sealed message too short")
	}
	ephemeralPub, rest := sealed[:keySize], sealed[keySize:]

	ephemeral, err := curve.NewPublicKey(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}
	shared, err := priv.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}

	gcm, err := deriveGCM(shared, ephemeralPub, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(rest) < ns {
		return nil, errors.New("sealed message too short")
	}
	nonce, ciphertext := rest[:ns], rest[ns:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("hybrid decryption failed")
	}
	return plaintext, nil
}

// deriveGCM turns the shared secret into an AES-256-GCM cipher, binding both public keys as HKDF salt.
func deriveGCM(shared, ephemeralPub, recipientPub []byte) (cipher.AEAD, error) {
	salt := append(append([]byte{}, ephemeralPub...), recipientPub...)
	key, err := hkdf.Key(sha256.New, shared, salt, hkdfInfo, keySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
