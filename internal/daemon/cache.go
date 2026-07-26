package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// Cache is the daemon's authoritative set of authorized keys, it is mutex-guarded.
// Every change is persisted to cache.json as the last-known-good fallback.
type Cache struct {
	mu      sync.RWMutex
	seq     uint64
	entries map[string]protocol.AccessEntry
	store   *Store
}

type persistedCache struct {
	Seq     uint64                 `json:"seq"`
	Entries []protocol.AccessEntry `json:"entries"`
}

// LoadCache reads the persisted cache. A missing file is not an error — a fresh
// daemon simply starts empty and fills in from the control plane's snapshot.
func (s *Store) LoadCache() (*Cache, error) {
	c := &Cache{entries: map[string]protocol.AccessEntry{}, store: s}
	data, err := os.ReadFile(s.path(cacheFile))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var pc persistedCache
	if err := json.Unmarshal(data, &pc); err != nil {
		return nil, err
	}
	c.seq = pc.Seq
	for _, e := range pc.Entries {
		c.entries[e.Fingerprint] = e
	}
	return c, nil
}

// Seq is the sequence number of the last applied snapshot.
func (c *Cache) Seq() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.seq
}

// Lookup returns the entry for a key fingerprint, if it is authorized here.
func (c *Cache) Lookup(fingerprint string) (protocol.AccessEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[fingerprint]
	return e, ok
}

func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Purge clears every entry and persists the empty set, so the last-known-good file authorizes no one.
func (c *Cache) Purge() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]protocol.AccessEntry{}
	return c.persistLocked()
}

// ApplySnapshot replaces the whole cache with the control plane's authoritative
// set. This is the reconcile path used on every (re)connect.
func (c *Cache) ApplySnapshot(snap protocol.Snapshot, seq uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]protocol.AccessEntry, len(snap.Entries))
	for _, e := range snap.Entries {
		c.entries[e.Fingerprint] = e
	}
	c.seq = seq
	return c.persistLocked()
}

// ApplyGrant adds or updates a single authorized key.
func (c *Cache) ApplyGrant(g protocol.Grant) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[g.Entry.Fingerprint] = g.Entry
	return c.persistLocked()
}

// ApplyRevoke removes a single authorized key.
func (c *Cache) ApplyRevoke(r protocol.Revoke) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, r.Fingerprint)
	return c.persistLocked()
}

// persistLocked writes the current entries to cache.json. The caller must hold
// the write lock; writes come from a single connection goroutine, so the tiny
// disk write under lock only briefly delays concurrent lookups.
func (c *Cache) persistLocked() error {
	entries := make([]protocol.AccessEntry, 0, len(c.entries))
	for _, e := range c.entries {
		entries = append(entries, e)
	}
	data, err := json.Marshal(persistedCache{Seq: c.seq, Entries: entries})
	if err != nil {
		return err
	}
	return atomicWrite(c.store.path(cacheFile), data, 0o600)
}
