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

type createSecretRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type updateSecretRequest struct {
	Value string `json:"value"`
}

type secretView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type secretValueView struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	if s.wrapper == nil {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
		return
	}
	auth := authFrom(r.Context())
	if !s.canGlobal(r.Context(), auth, "secret.add") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req createSecretRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Value == "" {
		http.Error(w, "name and value are required", http.StatusBadRequest)
		return
	}

	sealed, err := vault.Seal(r.Context(), s.wrapper, []byte(req.Value))
	if err != nil {
		serverError(w, "could not seal secret", err)
		return
	}
	secret, err := s.q.CreateSecret(r.Context(), db.CreateSecretParams{
		Name:       req.Name,
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		WrappedKey: sealed.WrappedKey,
		CreatedBy:  auth.UserID,
	})
	if err != nil {
		serverError(w, "could not create secret", err)
		return
	}
	s.auditSecret(r.Context(), secret.ID, secret.Name, "add", auth.UserID)
	s.writeResponse(w, auth.ClientPublicKey, toSecretView(secret))
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	views := []secretView{}

	if auth.Role == "admin" {
		rows, err := s.q.ListAllSecrets(r.Context())
		if err != nil {
			serverError(w, "could not list secrets", err)
			return
		}
		for _, row := range rows {
			views = append(views, secretView{uuidString(row.ID), row.Name, row.CreatedAt.Time, row.UpdatedAt.Time})
		}
	} else {
		rows, err := s.q.ListReadableSecrets(r.Context(), auth.UserID)
		if err != nil {
			serverError(w, "could not list secrets", err)
			return
		}
		for _, row := range rows {
			views = append(views, secretView{uuidString(row.ID), row.Name, row.CreatedAt.Time, row.UpdatedAt.Time})
		}
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	if s.wrapper == nil {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
		return
	}
	auth := authFrom(r.Context())
	secretID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	if !s.canSecret(r.Context(), auth, "secret.read", secretID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	secret, err := s.q.GetSecret(r.Context(), secretID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not read secret", err)
		return
	}
	plaintext, err := vault.Open(r.Context(), s.wrapper, vault.Sealed{
		Ciphertext: secret.Ciphertext, Nonce: secret.Nonce, WrappedKey: secret.WrappedKey,
	})
	if err != nil {
		serverError(w, "could not open secret", err)
		return
	}
	s.auditSecret(r.Context(), secret.ID, secret.Name, "read", auth.UserID)
	s.writeResponse(w, auth.ClientPublicKey, secretValueView{
		ID: uuidString(secret.ID), Name: secret.Name, Value: string(plaintext),
	})
}

func (s *Server) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	if s.wrapper == nil {
		http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
		return
	}
	auth := authFrom(r.Context())
	secretID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	if !s.canSecret(r.Context(), auth, "secret.update", secretID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req updateSecretRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Value == "" {
		http.Error(w, "value is required", http.StatusBadRequest)
		return
	}

	sealed, err := vault.Seal(r.Context(), s.wrapper, []byte(req.Value))
	if err != nil {
		serverError(w, "could not seal secret", err)
		return
	}
	secret, err := s.q.UpdateSecret(r.Context(), db.UpdateSecretParams{
		ID: secretID, Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce, WrappedKey: sealed.WrappedKey,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not update secret", err)
		return
	}
	s.auditSecret(r.Context(), secret.ID, secret.Name, "update", auth.UserID)
	s.writeResponse(w, auth.ClientPublicKey, toSecretView(secret))
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	secretID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}
	if !s.canSecret(r.Context(), auth, "secret.delete", secretID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	secret, err := s.q.GetSecret(r.Context(), secretID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not delete secret", err)
		return
	}
	if err := s.q.DeleteSecret(r.Context(), secretID); err != nil {
		serverError(w, "could not delete secret", err)
		return
	}
	// Audit after delete with a null secret_id (the row is gone); the name is
	// denormalized so the entry stays legible.
	s.auditSecret(r.Context(), pgtype.UUID{}, secret.Name, "delete", auth.UserID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auditSecret(ctx context.Context, secretID pgtype.UUID, name, action string, userID pgtype.UUID) {
	s.q.InsertSecretAudit(ctx, db.InsertSecretAuditParams{
		SecretID: secretID, SecretName: name, Action: action, UserID: userID,
	})
}

func toSecretView(sec db.Secret) secretView {
	return secretView{
		ID:        uuidString(sec.ID),
		Name:      sec.Name,
		CreatedAt: sec.CreatedAt.Time,
		UpdatedAt: sec.UpdatedAt.Time,
	}
}
