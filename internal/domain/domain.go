// Package domain defines the core entities shared across custos.
package domain

import "time"

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

type User struct {
	ID        string
	Email     string
	Role      Role
	CreatedAt time.Time
}

// PublicKey is an SSH key registered to a user. Blob is unique system-wide:
// a key identifies exactly one person.
type PublicKey struct {
	ID          string
	UserID      string
	Type        string // e.g. "ssh-ed25519"
	Blob        string // base64 key body, without type prefix or comment
	Fingerprint string // SHA256, derived from Type+Blob
	Label       string
	CreatedAt   time.Time
}

// Host is a machine running custosd. Identity is the daemon's own public key,
// registered at enrollment and used to authenticate its live connection.
type Host struct {
	ID        string
	Name      string
	Identity  string // base64 daemon public key
	CreatedAt time.Time
}

type ResourceGroup struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

// Secret is an encrypted credential. Ciphertext, Nonce, and WrappedKey are the
// sealed form produced by the vault; none is sensitive without the master key.
type Secret struct {
	ID         string
	Name       string
	GroupID    string // optional
	Ciphertext []byte
	Nonce      []byte
	WrappedKey []byte
	CreatedAt  time.Time
}

type ResourceKind string

const (
	KindSecret ResourceKind = "secret"
	KindHost   ResourceKind = "host"
	KindGroup  ResourceKind = "group"
)

// Grant gives a user access to one resource. Granting a group cascades to its
// members; that expansion happens in the control plane, not here.
type Grant struct {
	ID        string
	UserID    string
	Kind      ResourceKind
	Target    string // resource ID
	GrantedBy string // admin user ID
	CreatedAt time.Time
}
