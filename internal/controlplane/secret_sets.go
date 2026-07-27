package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/hybrid"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
	"github.com/tofunmiadewuyi/custos/internal/vault"
)

type setEntryInput struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type createSetRequest struct {
	Name    string          `json:"name"`
	Entries []setEntryInput `json:"entries"`
}

// updateSetRequest replaces the whole entry set, mirroring a re-pasted .env.
type updateSetRequest struct {
	Entries []setEntryInput `json:"entries"`
}

type setView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Keys      []string  `json:"keys"` // env var names; values are never returned here
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Server) handleCreateSet(w http.ResponseWriter, r *http.Request) {
	if s.wrapper == nil {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
		return
	}
	auth := authFrom(r.Context())
	if !s.canGlobal(r.Context(), auth, "set.add") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req createSetRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if err := validateEntries(req.Entries); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not create set", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	set, err := q.CreateSet(r.Context(), db.CreateSetParams{Name: req.Name, CreatedBy: auth.UserID})
	if isUniqueViolation(err) {
		http.Error(w, "a set with that name already exists", http.StatusConflict)
		return
	}
	if err != nil {
		serverError(w, "could not create set", err)
		return
	}
	if err := s.sealEntries(r.Context(), q, set.ID, req.Entries); err != nil {
		serverError(w, "could not seal entries", err)
		return
	}
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{SetName: set.Name, Action: "create", Actor: auth.UserID}); err != nil {
		serverError(w, "could not create set", err)
		return
	}
	if err := s.grantOwner(r.Context(), q, auth.UserID, "set", set.ID, "set.read", "set.manage"); err != nil {
		serverError(w, "could not create set", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not create set", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, setView{
		ID: uuidString(set.ID), Name: set.Name, Keys: entryKeys(req.Entries),
		CreatedAt: set.CreatedAt.Time, UpdatedAt: set.UpdatedAt.Time,
	})
}

func (s *Server) handleListSets(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	views := []setView{}
	if auth.Role == "admin" {
		rows, err := s.q.ListSets(r.Context())
		if err != nil {
			serverError(w, "could not list sets", err)
			return
		}
		for _, row := range rows {
			views = append(views, setView{
				ID: uuidString(row.ID), Name: row.Name,
				CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
			})
		}
	} else {
		rows, err := s.q.ListReadableSets(r.Context(), auth.UserID)
		if err != nil {
			serverError(w, "could not list sets", err)
			return
		}
		for _, row := range rows {
			views = append(views, setView{
				ID: uuidString(row.ID), Name: row.Name,
				CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
			})
		}
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

func (s *Server) handleGetSet(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	setID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid set id", http.StatusBadRequest)
		return
	}
	if !s.canSet(r.Context(), auth, "set.read", setID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	set, err := s.q.GetSet(r.Context(), setID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "set not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not load set", err)
		return
	}
	keys, err := s.q.ListSetKeys(r.Context(), setID)
	if err != nil {
		serverError(w, "could not load set", err)
		return
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, setView{
		ID: uuidString(set.ID), Name: set.Name, Keys: keys,
		CreatedAt: set.CreatedAt.Time, UpdatedAt: set.UpdatedAt.Time,
	})
}

func (s *Server) handleUpdateSet(w http.ResponseWriter, r *http.Request) {
	if s.wrapper == nil {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
		return
	}
	auth := authFrom(r.Context())
	setID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid set id", http.StatusBadRequest)
		return
	}
	if !s.canSet(r.Context(), auth, "set.manage", setID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req updateSetRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := validateEntries(req.Entries); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	set, err := s.q.GetSet(r.Context(), setID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "set not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not load set", err)
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not update set", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	if err := q.DeleteSetEntries(r.Context(), setID); err != nil {
		serverError(w, "could not update set", err)
		return
	}
	if err := s.sealEntries(r.Context(), q, setID, req.Entries); err != nil {
		serverError(w, "could not seal entries", err)
		return
	}
	if err := q.TouchSet(r.Context(), setID); err != nil {
		serverError(w, "could not update set", err)
		return
	}
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{SetName: set.Name, Action: "edit", Actor: auth.UserID}); err != nil {
		serverError(w, "could not update set", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not update set", err)
		return
	}
	s.pushSetToHosts(r.Context(), setID)
	s.writeResponse(w, auth.ClientPublicKey, setView{
		ID: uuidString(set.ID), Name: set.Name, Keys: entryKeys(req.Entries),
		CreatedAt: set.CreatedAt.Time, UpdatedAt: time.Now(),
	})
}

// pushSetToHosts re-pushes a changed set to every host currently bound to it.
func (s *Server) pushSetToHosts(ctx context.Context, setID pgtype.UUID) {
	hosts, err := s.q.HostsForSet(ctx, setID)
	if err != nil {
		return
	}
	for _, h := range hosts {
		s.pushSecretSets(ctx, h)
	}
}

func (s *Server) handleDeleteSet(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	setID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid set id", http.StatusBadRequest)
		return
	}
	if !s.canSet(r.Context(), auth, "set.manage", setID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	set, err := s.q.GetSet(r.Context(), setID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "set not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not delete set", err)
		return
	}
	// Bound hosts, grabbed before the cascade delete so we can push their removal.
	hosts, _ := s.q.HostsForSet(r.Context(), setID)

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not delete set", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	if _, err := q.DeleteSet(r.Context(), setID); err != nil {
		serverError(w, "could not delete set", err)
		return
	}
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{SetName: set.Name, Action: "delete", Actor: auth.UserID}); err != nil {
		serverError(w, "could not delete set", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not delete set", err)
		return
	}
	for _, h := range hosts {
		s.pushSecretSets(r.Context(), h)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleBindSet(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	hostID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	var req struct {
		SetID  string `json:"set_id"`
		AsUser string `json:"as_user"`
	}
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	setID, err := parseUUID(req.SetID)
	if err != nil {
		http.Error(w, "invalid set_id", http.StatusBadRequest)
		return
	}
	// Binding exposes the set's secrets to the host: authority over both ends.
	if !s.canSet(r.Context(), auth, "set.read", setID) || !s.canHost(r.Context(), auth, "host.access", hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	set, err := s.q.GetSet(r.Context(), setID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "set not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not bind set", err)
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not bind set", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	if err := q.BindSet(r.Context(), db.BindSetParams{
		HostID: hostID, SetID: setID, AsUser: pgText(req.AsUser), GrantedBy: auth.UserID,
	}); err != nil {
		serverError(w, "could not bind set", err)
		return
	}
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{
		SetName: set.Name, HostID: hostID, Action: "deliver", Actor: auth.UserID,
	}); err != nil {
		serverError(w, "could not bind set", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not bind set", err)
		return
	}
	s.pushSecretSets(r.Context(), hostID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUnbindSet(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	hostID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	setID, err := parseUUID(chi.URLParam(r, "setId"))
	if err != nil {
		http.Error(w, "invalid set id", http.StatusBadRequest)
		return
	}
	if !s.canSet(r.Context(), auth, "set.read", setID) || !s.canHost(r.Context(), auth, "host.access", hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	n, err := s.q.UnbindSet(r.Context(), db.UnbindSetParams{HostID: hostID, SetID: setID})
	if err != nil {
		serverError(w, "could not unbind set", err)
		return
	}
	if n == 0 {
		http.Error(w, "binding not found", http.StatusNotFound)
		return
	}
	s.pushSecretSets(r.Context(), hostID) // host now receives the set removed
	w.WriteHeader(http.StatusNoContent)
}

// buildSecretSets resolves the host's bound sets, decrypts each entry, and seals
// the {key: value} map to the host's X25519 key. Empty when the host has no key.
func (s *Server) buildSecretSets(ctx context.Context, host db.Host) (protocol.SecretSets, error) {
	if s.wrapper == nil || host.EncryptionKey == "" {
		return protocol.SecretSets{}, nil
	}
	recipient, err := base64.StdEncoding.DecodeString(host.EncryptionKey)
	if err != nil {
		return protocol.SecretSets{}, err
	}
	rows, err := s.q.SetsForHost(ctx, host.ID)
	if err != nil {
		return protocol.SecretSets{}, err
	}
	sets := make([]protocol.SealedSet, 0, len(rows))
	for _, row := range rows {
		entries, err := s.q.GetSetEntries(ctx, row.ID)
		if err != nil {
			return protocol.SecretSets{}, err
		}
		m := make(map[string]string, len(entries))
		for _, e := range entries {
			val, err := vault.Open(ctx, s.wrapper, vault.Sealed{Ciphertext: e.Ciphertext, Nonce: e.Nonce, WrappedKey: e.WrappedKey})
			if err != nil {
				return protocol.SecretSets{}, err
			}
			m[e.Key] = string(val)
		}
		data, err := json.Marshal(m)
		if err != nil {
			return protocol.SecretSets{}, err
		}
		sealed, err := hybrid.Seal(recipient, data)
		if err != nil {
			return protocol.SecretSets{}, err
		}
		sets = append(sets, protocol.SealedSet{
			Name:    row.Name,
			AsUser:  textString(row.AsUser),
			Version: uint64(row.UpdatedAt.Time.UnixNano()),
			Sealed:  sealed,
		})
	}
	return protocol.SecretSets{Sets: sets}, nil
}

// secretSetsEnvelope marshals the sets, stamps the next per-host set-seq, and signs
// it under the sets tag. An unset signer (tests) yields an unsigned envelope.
func (s *Server) secretSetsEnvelope(ctx context.Context, hostID pgtype.UUID, sets protocol.SecretSets) (protocol.Envelope, error) {
	data, err := json.Marshal(sets)
	if err != nil {
		return protocol.Envelope{}, err
	}
	env := protocol.Envelope{Type: protocol.TypeSecretSets, Data: data}
	if s.signer == nil {
		return env, nil
	}
	seq, err := s.q.NextHostSetSeq(ctx, hostID)
	if err != nil {
		return protocol.Envelope{}, err
	}
	env.Seq = uint64(seq)
	env.Sig = s.signer.Sign(protocol.SecretSetsSigningInput(uuidString(hostID), env.Seq, data))
	return env, nil
}

// pushSecretSets rebuilds and pushes the host's sealed sets to its live connection.
func (s *Server) pushSecretSets(ctx context.Context, hostID pgtype.UUID) {
	host, err := s.q.GetHostByID(ctx, hostID)
	if err != nil {
		return
	}
	sets, err := s.buildSecretSets(ctx, host)
	if err != nil {
		return
	}
	env, err := s.secretSetsEnvelope(ctx, hostID, sets)
	if err != nil {
		return
	}
	s.hub.push(uuidString(hostID), env)
}

// sealEntries seals each value and inserts it as an individual set entry.
func (s *Server) sealEntries(ctx context.Context, q *db.Queries, setID pgtype.UUID, entries []setEntryInput) error {
	for _, e := range entries {
		sealed, err := vault.Seal(ctx, s.wrapper, []byte(e.Value))
		if err != nil {
			return err
		}
		if err := q.CreateSetEntry(ctx, db.CreateSetEntryParams{
			SetID: setID, Key: e.Key, Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce, WrappedKey: sealed.WrappedKey,
		}); err != nil {
			return err
		}
	}
	return nil
}

// validateEntries rejects empty or duplicate keys — the .env invariants.
func validateEntries(entries []setEntryInput) error {
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.Key == "" {
			return errors.New("entry key is required")
		}
		if seen[e.Key] {
			return errors.New("duplicate key: " + e.Key)
		}
		seen[e.Key] = true
	}
	return nil
}

func entryKeys(entries []setEntryInput) []string {
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	return keys
}
