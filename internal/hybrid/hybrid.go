// Package hybrid provides hybrid public-key encryption for API<->frontend
// payloads. An ephemeral X25519 key agreement (ECDH) derives a one-time
// AES-256-GCM key, so the sender can encrypt directly to the recipient's public
// key and TLS-terminating intermediaries never see plaintext.
//
// To decrypt, a recipient needs only its own private key plus the ephemeral
// public key carried in the message. The ephemeral keypair is generated and
// discarded inside Seal, per message.
//
// Wire format of a sealed message: ephemeralPublicKey(32) ‖ nonce(12) ‖ ciphertext.
package hybrid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	keySize  = 32
	hkdfInfo = "custos-hybrid:v1"
)

// GenerateKeyPair returns a new static X25519 keypair as raw bytes. The caller
// keeps the private key and publishes the public key to whoever encrypts to it.
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// Seal encrypts plaintext to recipientPublic. The returned message is
// self-contained and safe to hand to any transport.
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

// deriveGCM turns the shared secret into an AES-256-GCM cipher, binding both
// public keys into the derivation so the key is tied to this exact exchange.
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
