// Package identity handles host authentication: a daemon owns an Ed25519
// keypair, registers its public key at enrollment, and proves who it is on
// every reconnect by signing a challenge the control plane can verify.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// authContext is a domain-separation prefix mixed into every signature so a
// signature made for host auth cannot be replayed as any other kind.
const authContext = "custos-host-auth:v1:"

const challengeSize = 32

// KeyPair is a daemon's identity keypair. The private key stays on the host;
// only the public key is ever sent to or stored by the control plane.
type KeyPair struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{priv: priv, pub: pub}, nil
}

// LoadKeyPair restores a keypair from a base64 private key persisted on disk.
func LoadKeyPair(privateKey string) (*KeyPair, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key length")
	}
	priv := ed25519.PrivateKey(raw)
	return &KeyPair{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// PublicKey is the base64 form sent at enrollment and stored as Host.Identity.
func (k *KeyPair) PublicKey() string {
	return base64.StdEncoding.EncodeToString(k.pub)
}

// PrivateKey is the base64 form the daemon persists locally (file mode 0600).
func (k *KeyPair) PrivateKey() string {
	return base64.StdEncoding.EncodeToString(k.priv)
}

func (k *KeyPair) Sign(challenge []byte) []byte {
	return ed25519.Sign(k.priv, message(challenge))
}

// NewChallenge returns a fresh random nonce for the control plane to send.
func NewChallenge() ([]byte, error) {
	nonce := make([]byte, challengeSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// Verify checks that signature was produced for challenge by the private key
// matching publicKey (the base64 form registered at enrollment).
func Verify(publicKey string, challenge, signature []byte) error {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}
	if len(raw) != ed25519.PublicKeySize {
		return errors.New("invalid public key length")
	}
	if !ed25519.Verify(ed25519.PublicKey(raw), message(challenge), signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

func message(challenge []byte) []byte {
	return append([]byte(authContext), challenge...)
}
