// Package daemon implements custosd: the per-host agent that answers sshd's
// authorized-key lookups and stays in sync with the control plane.
package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/hybrid"
	"github.com/tofunmiadewuyi/custos/internal/identity"
)

const (
	DefaultDir = "/var/lib/custos"

	configFile     = "config.json"
	identityFile   = "identity.key"
	encryptionFile = "encryption.key"
	cacheFile      = "cache.json"
	statusFile     = "status.json"
)

// LiveStatus is the daemon's runtime state, written on connect/disconnect so a
// separate `custosd status` process can read the last-known live state.
type LiveStatus struct {
	Connected bool      `json:"connected"`
	LastSeq   uint64    `json:"last_seq"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Config is the daemon's persisted settings, written at enrollment.
type Config struct {
	ControlPlane     string `json:"control_plane"`
	HostID           string `json:"host_id"`
	SigningPublicKey string `json:"signing_public_key"`
}

// Store is the daemon's on-disk state directory.
type Store struct {
	dir string
}

// OpenStore ensures the state directory exists (private to the daemon user).
func OpenStore(dir string) (*Store, error) {
	if dir == "" {
		dir = DefaultDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Enrolled reports whether this host has an identity key yet.
func (s *Store) Enrolled() bool {
	_, err := os.Stat(s.path(identityFile))
	return err == nil
}

func (s *Store) LoadConfig() (Config, error) {
	var c Config
	data, err := os.ReadFile(s.path(configFile))
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(data, &c)
}

func (s *Store) SaveConfig(c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path(configFile), data, 0o600)
}

func (s *Store) LoadIdentity() (*identity.KeyPair, error) {
	data, err := os.ReadFile(s.path(identityFile))
	if err != nil {
		return nil, err
	}
	return identity.LoadKeyPair(string(data))
}

func (s *Store) SaveIdentity(kp *identity.KeyPair) error {
	return atomicWrite(s.path(identityFile), []byte(kp.PrivateKey()), 0o600)
}

// SaveEncryptionKey persists the daemon's X25519 keypair for sealed secret sets.
func (s *Store) SaveEncryptionKey(kp *hybrid.KeyPair) error {
	return atomicWrite(s.path(encryptionFile), []byte(kp.PrivateKey()), 0o600)
}

func (s *Store) LoadEncryptionKey() (*hybrid.KeyPair, error) {
	data, err := os.ReadFile(s.path(encryptionFile))
	if err != nil {
		return nil, err
	}
	return hybrid.LoadKeyPair(string(data))
}

func (s *Store) SaveStatus(st LiveStatus) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return atomicWrite(s.path(statusFile), data, 0o600)
}

func (s *Store) LoadStatus() (LiveStatus, error) {
	var st LiveStatus
	data, err := os.ReadFile(s.path(statusFile))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(data, &st)
}

func (s *Store) path(name string) string {
	return filepath.Join(s.dir, name)
}

// atomicWrite writes to a temp file in the same directory and renames it into
// place, so a crash mid-write can never leave a partial file.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
