package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
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
	s.writeResponse(w, auth.ClientPublicKey, setView{
		ID: uuidString(set.ID), Name: set.Name, Keys: entryKeys(req.Entries),
		CreatedAt: set.CreatedAt.Time, UpdatedAt: time.Now(),
	})
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
	w.WriteHeader(http.StatusNoContent)
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
