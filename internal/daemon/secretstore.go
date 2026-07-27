package daemon

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/tofunmiadewuyi/custos/internal/hybrid"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// SecretStore holds the host's opened machine-secret sets in memory only, never on disk.
type SecretStore struct {
	mu   sync.RWMutex
	seq  uint64
	sets map[string]openedSet // by set name
	key  *hybrid.KeyPair      // opens sealed payloads; nil = machine secrets disabled
}

type openedSet struct {
	asUser  string
	version uint64
	values  map[string]string
}

func NewSecretStore(key *hybrid.KeyPair) *SecretStore {
	return &SecretStore{sets: map[string]openedSet{}, key: key}
}

// Seq is the sequence number of the last applied push.
func (s *SecretStore) Seq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seq
}

// Apply opens the sealed bundle and replaces the whole in-memory set.
func (s *SecretStore) Apply(sealed protocol.SealedSecretSets, seq uint64) error {
	if s.key == nil {
		return errors.New("no encryption key; machine secrets disabled")
	}
	// Open before the lock so decryption doesn't block concurrent reads.
	plaintext, err := s.key.Open(sealed.Sealed)
	if err != nil {
		return err
	}
	var bundle protocol.SecretSets
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return err
	}
	opened := make(map[string]openedSet, len(bundle.Sets))
	for _, set := range bundle.Sets {
		opened[set.Name] = openedSet{asUser: set.AsUser, version: set.Version, values: set.Values}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets = opened
	s.seq = seq
	return nil
}

// Get returns a copy of a set's values plus the unix account it's scoped to, if any.
func (s *SecretStore) Get(name string) (values map[string]string, asUser string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set, ok := s.sets[name]
	if !ok {
		return nil, "", false
	}
	out := make(map[string]string, len(set.values))
	for k, v := range set.values {
		out[k] = v
	}
	return out, set.asUser, true
}
