package controlplane

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

type createEnrollTokenRequest struct {
	Accounts []string `json:"accounts"`
	Label    string   `json:"label"`
	TTLHours int      `json:"ttl_hours"`
}

type createEnrollTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleCreateEnrollToken(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	if !s.canGlobal(r.Context(), auth, "host.add") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req createEnrollTokenRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(req.Accounts) == 0 {
		http.Error(w, "accounts are required", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = time.Hour
	}

	raw, hash, err := GenerateToken()
	if err != nil {
		serverError(w, "internal error", err)
		return
	}
	expiresAt := time.Now().Add(ttl)
	if _, err := s.q.CreateEnrollmentToken(r.Context(), db.CreateEnrollmentTokenParams{
		TokenHash: hash,
		Label:     pgtype.Text{String: req.Label, Valid: req.Label != ""},
		Accounts:  req.Accounts,
		CreatedBy: auth.UserID,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		serverError(w, "could not create token", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, createEnrollTokenResponse{Token: raw, ExpiresAt: expiresAt})
}
