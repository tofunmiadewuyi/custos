// Package protocol defines the messages exchanged between custosd and the
// control plane: a one-shot HTTP enrollment, then a long-lived websocket
// session carrying access updates and audit logs.
package protocol

import (
	"encoding/json"
	"time"
)

// EnrollRequest/EnrollResponse are a plain HTTP request/response, done once
// when a daemon first joins. It registers the daemon's identity public key;
// every later websocket connection is authenticated by signing a challenge
// with the matching private key.
type EnrollRequest struct {
	Token     string `json:"token"` // admin-issued, single-use
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"` // daemon identity, base64
}

type EnrollResponse struct {
	HostID string `json:"host_id"`
}

// MessageType tags an Envelope so the receiver knows how to decode Data.
type MessageType string

const (
	// control plane -> daemon
	TypeChallenge MessageType = "challenge"
	TypeSnapshot  MessageType = "snapshot"
	TypeGrant     MessageType = "grant"
	TypeRevoke    MessageType = "revoke"
	TypePing      MessageType = "ping"

	// daemon -> control plane
	TypeAuth      MessageType = "auth"
	TypeAccessLog MessageType = "access_log"
	TypePong      MessageType = "pong"
)

// Envelope is the frame for every websocket message. Data holds the encoded
// payload for Type, or is empty for messages that carry none (ping/pong).
type Envelope struct {
	Type MessageType     `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

func NewEnvelope(t MessageType, payload any) (Envelope, error) {
	if payload == nil {
		return Envelope{Type: t}, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Type: t, Data: data}, nil
}

// Challenge is sent by the control plane when a daemon connects. The daemon
// signs Nonce with its identity key to prove it is the host it claims to be.
type Challenge struct {
	Nonce []byte `json:"nonce"`
}

// Auth answers a Challenge: the daemon names itself and returns its signature
// over the nonce. The control plane verifies it against the host's stored key.
type Auth struct {
	HostID    string `json:"host_id"`
	Signature []byte `json:"signature"`
}

// AccessEntry is one authorized key on a server: enough to match the key sshd
// presents, decide which local accounts it may log in as, and record who used
// it. The daemon holds no local policy; Accounts is authoritative from the
// control plane.
type AccessEntry struct {
	UserID      string   `json:"user_id"`
	KeyType     string   `json:"key_type"`
	KeyBlob     string   `json:"key_blob"`
	Fingerprint string   `json:"fingerprint"`
	Accounts    []string `json:"accounts"` // local accounts this key may log in as
}

// Snapshot is the full authoritative set of authorized keys, sent on every
// (re)connect. The daemon replaces its cache with this; it is the source of
// truth that the incremental Grant/Revoke stream then updates.
type Snapshot struct {
	Entries []AccessEntry `json:"entries"`
}

type Grant struct {
	Entry AccessEntry `json:"entry"`
}

type Revoke struct {
	Fingerprint string `json:"fingerprint"`
}

// AccessLog reports one login attempt sshd asked about. Sent best-effort; the
// daemon also keeps it locally so nothing is lost while the connection is down.
type AccessLog struct {
	Fingerprint string    `json:"fingerprint"`
	Account     string    `json:"account"`
	Allowed     bool      `json:"allowed"`
	At          time.Time `json:"at"`
}
