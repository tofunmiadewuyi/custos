package controlplane

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const auditFeedLimit = 100

type auditEntry struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	At         time.Time `json:"at"`
	SecretID   string    `json:"secret_id"` // "" once the secret is deleted
	SecretName string    `json:"secret_name"`
	UserID     string    `json:"user_id"` // "" if the user was removed
	UserEmail  string    `json:"user_email"`
}

// handleSecretAudit returns the access/change history for one secret. Anyone who
// may read the secret may see who else has.
func (s *Server) handleSecretAudit(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.q.ListSecretAudit(r.Context(), secretID)
	if err != nil {
		serverError(w, "could not load audit", err)
		return
	}
	entries := make([]auditEntry, 0, len(rows))
	for _, a := range rows {
		entries = append(entries, auditEntry{
			ID: uuidString(a.ID), Action: a.Action, At: a.At.Time,
			SecretID: uuidString(a.SecretID), SecretName: a.SecretName,
			UserID: uuidString(a.UserID), UserEmail: textString(a.UserEmail),
		})
	}
	s.writeResponse(w, auth.ClientPublicKey, entries)
}

// handleAllAudit returns the most recent secret events across the system (admin).
func (s *Server) handleAllAudit(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	rows, err := s.q.ListAllSecretAudit(r.Context(), auditFeedLimit)
	if err != nil {
		serverError(w, "could not load audit", err)
		return
	}
	entries := make([]auditEntry, 0, len(rows))
	for _, a := range rows {
		entries = append(entries, auditEntry{
			ID: uuidString(a.ID), Action: a.Action, At: a.At.Time,
			SecretID: uuidString(a.SecretID), SecretName: a.SecretName,
			UserID: uuidString(a.UserID), UserEmail: textString(a.UserEmail),
		})
	}
	s.writeResponse(w, auth.ClientPublicKey, entries)
}

func textString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}
