package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/vault"
)

// secretFields are the sealed-at-rest parts of a credential, stored as one
// encrypted JSON blob.
type secretFields struct {
	Password string `json:"password,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

func (f secretFields) empty() bool { return f.Password == "" && f.Notes == "" }

type createSecretRequest struct {
	Label        string `json:"label"`
	URL          string `json:"url"`
	Username     string `json:"username"`
	OTPRecipient string `json:"otp_recipient"`
	Password     string `json:"password"`
	Notes        string `json:"notes"`
}

type updateSecretRequest = createSecretRequest

type actor struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

type secretView struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	URL          string    `json:"url"`
	Username     string    `json:"username"`
	OTPRecipient string    `json:"otp_recipient"`
	CreatedBy    *actor    `json:"created_by"`
	UpdatedBy    *actor    `json:"updated_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type secretDetailView struct {
	secretView
	Password string `json:"password"`
	Notes    string `json:"notes"`
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
	if req.Label == "" {
		http.Error(w, "label is required", http.StatusBadRequest)
		return
	}

	ct, nonce, wrapped, err := s.sealFields(r.Context(), req)
	if err != nil {
		serverError(w, "could not seal secret", err)
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not create secret", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	secret, err := q.CreateSecret(r.Context(), db.CreateSecretParams{
		Label:        req.Label,
		Url:          pgText(req.URL),
		Username:     pgText(req.Username),
		OtpRecipient: pgText(req.OTPRecipient),
		Ciphertext:   ct,
		Nonce:        nonce,
		WrappedKey:   wrapped,
		CreatedBy:    auth.UserID,
		UpdatedBy:    auth.UserID,
	})
	if err != nil {
		serverError(w, "could not create secret", err)
		return
	}
	if err := q.InsertSecretAudit(r.Context(), db.InsertSecretAuditParams{
		SecretID: secret.ID, SecretName: secret.Label, Action: "add", UserID: auth.UserID,
	}); err != nil {
		serverError(w, "could not create secret", err)
		return
	}
	if err := s.grantOwner(r.Context(), q, auth.UserID, "secret", secret.ID, "secret.read", "secret.update", "secret.delete"); err != nil {
		serverError(w, "could not create secret", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not create secret", err)
		return
	}
	s.respondSecret(w, r, auth, secret.ID)
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
			views = append(views, secretView{
				ID: uuidString(row.ID), Label: row.Label,
				URL: textString(row.Url), Username: textString(row.Username), OTPRecipient: textString(row.OtpRecipient),
				CreatedBy: actorOf(row.CreatedBy, row.CreatedByName, row.CreatedByDisplayName, row.CreatedByEmail),
				UpdatedBy: actorOf(row.UpdatedBy, row.UpdatedByName, row.UpdatedByDisplayName, row.UpdatedByEmail),
				CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
			})
		}
	} else {
		rows, err := s.q.ListReadableSecrets(r.Context(), auth.UserID)
		if err != nil {
			serverError(w, "could not list secrets", err)
			return
		}
		for _, row := range rows {
			views = append(views, secretView{
				ID: uuidString(row.ID), Label: row.Label,
				URL: textString(row.Url), Username: textString(row.Username), OTPRecipient: textString(row.OtpRecipient),
				CreatedBy: actorOf(row.CreatedBy, row.CreatedByName, row.CreatedByDisplayName, row.CreatedByEmail),
				UpdatedBy: actorOf(row.UpdatedBy, row.UpdatedByName, row.UpdatedByDisplayName, row.UpdatedByEmail),
				CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
			})
		}
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

// handleGetSecret returns metadata only — no decryption, no read audit. Use
// handleRevealSecret to actually see the sealed fields.
func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
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
	row, err := s.q.GetSecret(r.Context(), secretID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not read secret", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, secretViewFromGet(row))
}

// handleRevealSecret decrypts and returns the sealed fields, and logs the read —
// this is the "show/copy password" action, distinct from viewing metadata.
func (s *Server) handleRevealSecret(w http.ResponseWriter, r *http.Request) {
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
	row, err := s.q.GetSecret(r.Context(), secretID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not read secret", err)
		return
	}
	fields, err := s.openFields(r.Context(), row.Ciphertext, row.Nonce, row.WrappedKey)
	if err != nil {
		serverError(w, "could not open secret", err)
		return
	}
	s.auditSecret(r.Context(), row.ID, row.Label, "read", auth.UserID)
	s.writeResponse(w, auth.ClientPublicKey, secretDetailView{
		secretView: secretViewFromGet(row),
		Password:   fields.Password,
		Notes:      fields.Notes,
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
	if req.Label == "" {
		http.Error(w, "label is required", http.StatusBadRequest)
		return
	}

	ct, nonce, wrapped, err := s.sealFields(r.Context(), req)
	if err != nil {
		serverError(w, "could not seal secret", err)
		return
	}
	secret, err := s.q.UpdateSecret(r.Context(), db.UpdateSecretParams{
		ID:           secretID,
		Label:        req.Label,
		Url:          pgText(req.URL),
		Username:     pgText(req.Username),
		OtpRecipient: pgText(req.OTPRecipient),
		Ciphertext:   ct,
		Nonce:        nonce,
		WrappedKey:   wrapped,
		UpdatedBy:    auth.UserID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not update secret", err)
		return
	}
	s.auditSecret(r.Context(), secret.ID, secret.Label, "update", auth.UserID)
	s.respondSecret(w, r, auth, secret.ID)
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
	row, err := s.q.GetSecret(r.Context(), secretID)
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
	// null secret_id (row is gone); the label is denormalized so the entry stays legible.
	s.auditSecret(r.Context(), pgtype.UUID{}, row.Label, "delete", auth.UserID)
	w.WriteHeader(http.StatusNoContent)
}

// respondSecret refetches the secret (to resolve actor emails) and returns its metadata view.
func (s *Server) respondSecret(w http.ResponseWriter, r *http.Request, auth authInfo, id pgtype.UUID) {
	row, err := s.q.GetSecret(r.Context(), id)
	if err != nil {
		serverError(w, "could not load secret", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, secretViewFromGet(row))
}

// sealFields packs the secret fields into one JSON blob and seals it. Returns
// nil columns when there are no secret fields.
func (s *Server) sealFields(ctx context.Context, req createSecretRequest) (ct, nonce, wrapped []byte, err error) {
	f := secretFields{Password: req.Password, Notes: req.Notes}
	if f.empty() {
		return nil, nil, nil, nil
	}
	data, err := json.Marshal(f)
	if err != nil {
		return nil, nil, nil, err
	}
	sealed, err := vault.Seal(ctx, s.wrapper, data)
	if err != nil {
		return nil, nil, nil, err
	}
	return sealed.Ciphertext, sealed.Nonce, sealed.WrappedKey, nil
}

func (s *Server) openFields(ctx context.Context, ct, nonce, wrapped []byte) (secretFields, error) {
	if ct == nil {
		return secretFields{}, nil
	}
	plaintext, err := vault.Open(ctx, s.wrapper, vault.Sealed{Ciphertext: ct, Nonce: nonce, WrappedKey: wrapped})
	if err != nil {
		return secretFields{}, err
	}
	var f secretFields
	if err := json.Unmarshal(plaintext, &f); err != nil {
		return secretFields{}, err
	}
	return f, nil
}

func (s *Server) auditSecret(ctx context.Context, secretID pgtype.UUID, label, action string, userID pgtype.UUID) {
	s.q.InsertSecretAudit(ctx, db.InsertSecretAuditParams{
		SecretID: secretID, SecretName: label, Action: action, UserID: userID,
	})
}

func secretViewFromGet(row db.GetSecretRow) secretView {
	return secretView{
		ID:           uuidString(row.ID),
		Label:        row.Label,
		URL:          textString(row.Url),
		Username:     textString(row.Username),
		OTPRecipient: textString(row.OtpRecipient),
		CreatedBy:    actorOf(row.CreatedBy, row.CreatedByName, row.CreatedByDisplayName, row.CreatedByEmail),
		UpdatedBy:    actorOf(row.UpdatedBy, row.UpdatedByName, row.UpdatedByDisplayName, row.UpdatedByEmail),
		CreatedAt:    row.CreatedAt.Time,
		UpdatedAt:    row.UpdatedAt.Time,
	}
}

func actorOf(id pgtype.UUID, name, displayName, email pgtype.Text) *actor {
	if !id.Valid {
		return nil
	}
	return &actor{
		ID:          uuidString(id),
		Name:        textString(name),
		DisplayName: textString(displayName),
		Email:       textString(email),
	}
}

// pgText wraps an optional string as a nullable column value.
func pgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}
