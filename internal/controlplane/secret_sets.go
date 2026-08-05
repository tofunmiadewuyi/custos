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

type updateSetRequest struct {
	Name string `json:"name"`
}

type setView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Keys        []string  `json:"keys"` // env var names; values are never returned here
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Permissions []string  `json:"permissions"`
}

type setListView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	KeyCount    int64     `json:"key_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Permissions []string  `json:"permissions"`
}

type setHostView struct {
	hostView
	AsUser  string    `json:"as_user,omitempty"`
	BoundAt time.Time `json:"bound_at"`
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
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{SetID: set.ID, SetName: set.Name, Action: "create", Actor: auth.UserID}); err != nil {
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
		Permissions: s.setPermissions(r.Context(), auth, set.ID),
	})
}

func (s *Server) handleListSets(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	views := []setListView{}
	if auth.Role == "admin" {
		rows, err := s.q.ListSets(r.Context())
		if err != nil {
			serverError(w, "could not list sets", err)
			return
		}
		for _, row := range rows {
			views = append(views, setListView{
				ID: uuidString(row.ID), Name: row.Name, KeyCount: row.KeyCount,
				CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
				Permissions: s.setPermissions(r.Context(), auth, row.ID),
			})
		}
	} else {
		rows, err := s.q.ListReadableSets(r.Context(), auth.UserID)
		if err != nil {
			serverError(w, "could not list sets", err)
			return
		}
		for _, row := range rows {
			views = append(views, setListView{
				ID: uuidString(row.ID), Name: row.Name, KeyCount: row.KeyCount,
				CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
				Permissions: s.setPermissions(r.Context(), auth, row.ID),
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
		Permissions: s.setPermissions(r.Context(), auth, set.ID),
	})
}

func (s *Server) handleListSetHosts(w http.ResponseWriter, r *http.Request) {
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
	if _, err := s.q.GetSet(r.Context(), setID); errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "set not found", http.StatusNotFound)
		return
	} else if err != nil {
		serverError(w, "could not load set", err)
		return
	}
	rows, err := s.q.ListHostsForSet(r.Context(), setID)
	if err != nil {
		serverError(w, "could not list set hosts", err)
		return
	}
	views := make([]setHostView, 0, len(rows))
	for _, h := range rows {
		views = append(views, setHostView{
			hostView: hostView{
				ID:               uuidString(h.ID),
				Name:             h.Name,
				Hostname:         h.Hostname,
				Accounts:         h.Accounts,
				Status:           h.Status,
				ConnectionStatus: s.hostConnectionStatus(h.ID, h.LastSeenAt),
				AgentVersion:     h.AgentVersion,
				DesiredVersion:   h.DesiredVersion,
				EnrolledAt:       h.EnrolledAt.Time,
				LastSeenAt:       nullTime(h.LastSeenAt),
				Permissions:      s.hostPermissions(r.Context(), auth, h.ID),
			},
			AsUser:  h.AsUser.String,
			BoundAt: h.BoundAt.Time,
		})
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

func (s *Server) handleUpdateSet(w http.ResponseWriter, r *http.Request) {
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
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if _, err := s.q.GetSet(r.Context(), setID); errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "set not found", http.StatusNotFound)
		return
	} else if err != nil {
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

	updated, err := q.UpdateSetName(r.Context(), db.UpdateSetNameParams{ID: setID, Name: req.Name})
	if isUniqueViolation(err) {
		http.Error(w, "a set with that name already exists", http.StatusConflict)
		return
	}
	if err != nil {
		serverError(w, "could not update set", err)
		return
	}
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{SetID: updated.ID, SetName: updated.Name, Action: "rename", Actor: auth.UserID}); err != nil {
		serverError(w, "could not update set", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not update set", err)
		return
	}
	s.pushSetToHosts(r.Context(), setID)
	keys, err := s.q.ListSetKeys(r.Context(), setID)
	if err != nil {
		serverError(w, "could not update set", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, setView{
		ID: uuidString(updated.ID), Name: updated.Name, Keys: keys,
		CreatedAt: updated.CreatedAt.Time, UpdatedAt: updated.UpdatedAt.Time,
		Permissions: s.setPermissions(r.Context(), auth, updated.ID),
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
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{SetID: set.ID, SetName: set.Name, Action: "delete", Actor: auth.UserID}); err != nil {
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
		SetID: setID, SetName: set.Name, HostID: hostID, Action: "deliver", Actor: auth.UserID,
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

// handleUpsertSetEntry adds or replaces a single entry — change one secret without
// re-sending the whole set.
func (s *Server) handleUpsertSetEntry(w http.ResponseWriter, r *http.Request) {
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
	key := chi.URLParam(r, "key")
	if key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
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
		serverError(w, "could not load set", err)
		return
	}
	var req struct {
		Value string `json:"value"`
	}
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	sealed, err := vault.Seal(r.Context(), s.wrapper, []byte(req.Value))
	if err != nil {
		serverError(w, "could not seal value", err)
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not update entry", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	if err := q.UpsertSetEntry(r.Context(), db.UpsertSetEntryParams{
		SetID: setID, Key: key, Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce, WrappedKey: sealed.WrappedKey,
	}); err != nil {
		serverError(w, "could not update entry", err)
		return
	}
	if err := q.TouchSet(r.Context(), setID); err != nil {
		serverError(w, "could not update entry", err)
		return
	}
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{
		SetID: setID, SetName: set.Name, EntryKey: pgText(key), Action: "edit", Actor: auth.UserID,
	}); err != nil {
		serverError(w, "could not update entry", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not update entry", err)
		return
	}
	s.pushSetToHosts(r.Context(), setID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteSetEntry(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	setID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid set id", http.StatusBadRequest)
		return
	}
	key := chi.URLParam(r, "key")
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
		serverError(w, "could not load set", err)
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not delete entry", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	n, err := q.DeleteSetEntry(r.Context(), db.DeleteSetEntryParams{SetID: setID, Key: key})
	if err != nil {
		serverError(w, "could not delete entry", err)
		return
	}
	if n == 0 {
		http.Error(w, "entry not found", http.StatusNotFound)
		return
	}
	if err := q.TouchSet(r.Context(), setID); err != nil {
		serverError(w, "could not delete entry", err)
		return
	}
	if err := q.InsertSetAudit(r.Context(), db.InsertSetAuditParams{
		SetID: setID, SetName: set.Name, EntryKey: pgText(key), Action: "edit", Actor: auth.UserID,
	}); err != nil {
		serverError(w, "could not delete entry", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not delete entry", err)
		return
	}
	s.pushSetToHosts(r.Context(), setID)
	w.WriteHeader(http.StatusNoContent)
}

type setAuditView struct {
	Action           string    `json:"action"`
	SetName          string    `json:"set_name"`
	EntryKey         string    `json:"entry_key,omitempty"`
	HostID           string    `json:"host_id,omitempty"`
	Actor            string    `json:"actor,omitempty"`
	ActorEmail       string    `json:"actor_email,omitempty"`
	ActorName        string    `json:"actor_name,omitempty"`
	ActorDisplayName string    `json:"actor_display_name,omitempty"`
	At               time.Time `json:"at"`
}

func (s *Server) handleSetAudit(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.q.ListSetAudit(r.Context(), db.ListSetAuditParams{SetID: setID, SetName: set.Name})
	if err != nil {
		serverError(w, "could not load audit", err)
		return
	}
	views := make([]setAuditView, 0, len(rows))
	for _, row := range rows {
		views = append(views, setAuditView{
			Action: row.Action, SetName: row.SetName,
			EntryKey: textString(row.EntryKey), HostID: uuidString(row.HostID), Actor: uuidString(row.Actor),
			ActorEmail: textString(row.ActorEmail), ActorName: textString(row.ActorName),
			ActorDisplayName: textString(row.ActorDisplayName), At: row.At.Time,
		})
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

// buildSecretSets resolves the host's bound sets and decrypts each entry into a
// cleartext bundle. Sealing happens once, in secretSetsEnvelope.
func (s *Server) buildSecretSets(ctx context.Context, host db.Host) (protocol.SecretSets, error) {
	if s.wrapper == nil {
		return protocol.SecretSets{}, nil
	}
	rows, err := s.q.SetsForHost(ctx, host.ID)
	if err != nil {
		return protocol.SecretSets{}, err
	}
	sets := make([]protocol.SecretSet, 0, len(rows))
	for _, row := range rows {
		entries, err := s.q.GetSetEntries(ctx, row.ID)
		if err != nil {
			return protocol.SecretSets{}, err
		}
		values := make(map[string]string, len(entries))
		for _, e := range entries {
			val, err := vault.Open(ctx, s.wrapper, vault.Sealed{Ciphertext: e.Ciphertext, Nonce: e.Nonce, WrappedKey: e.WrappedKey})
			if err != nil {
				return protocol.SecretSets{}, err
			}
			values[e.Key] = string(val)
		}
		sets = append(sets, protocol.SecretSet{
			Name:    row.Name,
			AsUser:  textString(row.AsUser),
			Version: uint64(row.UpdatedAt.Time.UnixNano()),
			Values:  values,
		})
	}
	return protocol.SecretSets{Sets: sets}, nil
}

// secretSetsEnvelope seals the whole bundle to the host's X25519 key as one blob,
// stamps the next per-host set-seq, and signs it under the sets tag.
func (s *Server) secretSetsEnvelope(ctx context.Context, host db.Host, sets protocol.SecretSets) (protocol.Envelope, error) {
	plain, err := json.Marshal(sets)
	if err != nil {
		return protocol.Envelope{}, err
	}
	recipient, err := base64.StdEncoding.DecodeString(host.EncryptionKey)
	if err != nil {
		return protocol.Envelope{}, err
	}
	sealed, err := hybrid.Seal(recipient, plain)
	if err != nil {
		return protocol.Envelope{}, err
	}
	data, err := json.Marshal(protocol.SealedSecretSets{Sealed: sealed})
	if err != nil {
		return protocol.Envelope{}, err
	}
	env := protocol.Envelope{Type: protocol.TypeSecretSets, Data: data}
	if s.signer == nil {
		return env, nil
	}
	seq, err := s.q.NextHostSetSeq(ctx, host.ID)
	if err != nil {
		return protocol.Envelope{}, err
	}
	env.Seq = uint64(seq)
	env.Sig = s.signer.Sign(protocol.SecretSetsSigningInput(uuidString(host.ID), env.Seq, data))
	return env, nil
}

// pushSecretSets rebuilds and pushes the host's sealed bundle to its live connection.
func (s *Server) pushSecretSets(ctx context.Context, hostID pgtype.UUID) {
	host, err := s.q.GetHostByID(ctx, hostID)
	if err != nil || host.EncryptionKey == "" {
		return
	}
	sets, err := s.buildSecretSets(ctx, host)
	if err != nil {
		return
	}
	env, err := s.secretSetsEnvelope(ctx, host, sets)
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
