// Package protocol defines the messages exchanged between custosd and the
// control plane: a one-shot HTTP enrollment, then a long-lived websocket
// session carrying access updates and audit logs.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"time"
)

// EnrollRequest/EnrollResponse are a plain HTTP request/response, done once
// when a daemon first joins. It registers the daemon's identity public key;
// every later websocket connection is authenticated by signing a challenge
// with the matching private key.
type EnrollRequest struct {
	Token         string `json:"token"` // admin-issued, single-use
	Hostname      string `json:"hostname"`
	PublicKey     string `json:"public_key"`     // daemon identity (ed25519, signing), base64
	EncryptionKey string `json:"encryption_key"` // daemon X25519 public key for sealed secrets, base64
	MachineID     string `json:"machine_id"`     // app-specific hash of /etc/machine-id; empty if unavailable
}

type EnrollResponse struct {
	HostID           string `json:"host_id"`
	SigningPublicKey string `json:"signing_public_key"` // control plane's ed25519 snapshot-signing key, base64
}

// MessageType tags an Envelope so the receiver knows how to decode Data.
type MessageType string

const (
	// control plane -> daemon
	TypeChallenge MessageType = "challenge"
	TypeSnapshot  MessageType = "snapshot"
	TypeGrant     MessageType = "grant"
	TypeRevoke    MessageType = "revoke"
	TypePing       MessageType = "ping"
	TypeUpgrade    MessageType = "upgrade"
	TypeSecretSets MessageType = "secret_sets"

	// daemon -> control plane
	TypeAuth      MessageType = "auth"
	TypeAccessLog MessageType = "access_log"
	TypePong      MessageType = "pong"
)

// Envelope is the frame for every websocket message. Data is empty for ping/pong.
type Envelope struct {
	Type MessageType     `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
	Seq  uint64          `json:"seq,omitempty"` // monotonic per-host; anti-replay
	Sig  []byte          `json:"sig,omitempty"` // ed25519 over SnapshotSigningInput
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

// Domain-separation tags: each signed message type gets its own so a signature
// for one can never be replayed as another.
const (
	snapshotSigTag = "custos-snapshot:v1"
	setsSigTag     = "custos-sets:v1"
)

// SnapshotSigningInput builds the signed bytes: tag ‖ len16(hostID) ‖ hostID ‖ seq(8 BE) ‖ data.
func SnapshotSigningInput(hostID string, seq uint64, data []byte) []byte {
	return signingInput(snapshotSigTag, hostID, seq, data)
}

// SecretSetsSigningInput is the same construction as snapshots under the sets tag.
func SecretSetsSigningInput(hostID string, seq uint64, data []byte) []byte {
	return signingInput(setsSigTag, hostID, seq, data)
}

func signingInput(tag, hostID string, seq uint64, data []byte) []byte {
	buf := make([]byte, 0, len(tag)+2+len(hostID)+8+len(data))
	buf = append(buf, tag...)
	var n [8]byte
	binary.BigEndian.PutUint16(n[:2], uint16(len(hostID)))
	buf = append(buf, n[:2]...)
	buf = append(buf, hostID...)
	binary.BigEndian.PutUint64(n[:], seq)
	buf = append(buf, n[:]...)
	buf = append(buf, data...)
	return buf
}

// Challenge is sent by the control plane when a daemon connects. The daemon
// signs Nonce with its identity key to prove it is the host it claims to be.
type Challenge struct {
	Nonce []byte `json:"nonce"`
}

// Auth answers a Challenge: the daemon names itself and returns its signature
// over the nonce. Version lets the control plane track drift + dedupe upgrades.
type Auth struct {
	HostID    string `json:"host_id"`
	Signature []byte `json:"signature"`
	Version   string `json:"version,omitempty"`
}

// Upgrade tells the daemon to fetch, verify, stage, and restart into a new build.
// SHA256 maps GOARCH -> tarball digest; supplied by the control plane = the trust anchor.
type Upgrade struct {
	Version string            `json:"version"`
	SHA256  map[string]string `json:"sha256"`
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

// SecretSet is one set in cleartext: env {KEY:value}, the unix account it's scoped to, and an edit version.
type SecretSet struct {
	Name    string            `json:"name"`
	AsUser  string            `json:"as_user,omitempty"`
	Version uint64            `json:"version"`
	Values  map[string]string `json:"values"`
}

// SecretSets is the full cleartext bundle for a host, sealed as one blob before sending.
type SecretSets struct {
	Sets []SecretSet `json:"sets"`
}

// SealedSecretSets is the TypeSecretSets payload: the whole bundle hybrid-sealed to the host key.
type SealedSecretSets struct {
	Sealed []byte `json:"sealed"`
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
