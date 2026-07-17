package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

var errInvalidToken = errors.New("invalid or expired enrollment token")

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Token == "" || req.PublicKey == "" {
		http.Error(w, "token and public_key are required", http.StatusBadRequest)
		return
	}

	hostID, err := s.enroll(r.Context(), req)
	if errors.Is(err, errInvalidToken) {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "enrollment failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, protocol.EnrollResponse{HostID: hostID})
}

// enroll validates the token, creates the host with the token's accounts, and
// consumes the token, all in one transaction.
func (s *Server) enroll(ctx context.Context, req protocol.EnrollRequest) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)

	tok, err := q.GetEnrollmentToken(ctx, HashToken(req.Token))
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errInvalidToken
	}
	if err != nil {
		return "", err
	}
	if tok.UsedAt.Valid || tok.ExpiresAt.Time.Before(time.Now()) {
		return "", errInvalidToken
	}

	host, err := q.CreateHost(ctx, db.CreateHostParams{
		Name:        req.Hostname,
		Hostname:    req.Hostname,
		IdentityKey: req.PublicKey,
		Accounts:    tok.Accounts,
	})
	if err != nil {
		return "", err
	}
	if err := q.MarkTokenUsed(ctx, db.MarkTokenUsedParams{ID: tok.ID, HostID: host.ID}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return uuidString(host.ID), nil
}
