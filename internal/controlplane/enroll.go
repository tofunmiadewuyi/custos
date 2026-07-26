package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

var (
	errInvalidToken    = errors.New("invalid or expired enrollment token")
	errAlreadyEnrolled = errors.New("host already enrolled")
)

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
	if errors.Is(err, errAlreadyEnrolled) {
		http.Error(w, "host already enrolled; revoke it before re-enrolling", http.StatusConflict)
		return
	}
	if err != nil {
		serverError(w, "enrollment failed", err)
		return
	}
	writeJSON(w, protocol.EnrollResponse{HostID: hostID, SigningPublicKey: s.signingPublicKey()})
}

func (s *Server) signingPublicKey() string {
	if s.signer == nil {
		return ""
	}
	return s.signer.PublicKey()
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

	// Guard: one active host per machine. A revoked host frees the machine to
	// re-enroll; an active one must be revoked first (deliberate admin action).
	machineID := pgtype.Text{String: req.MachineID, Valid: req.MachineID != ""}
	if machineID.Valid {
		if _, err := q.GetActiveHostByMachineID(ctx, machineID); err == nil {
			return "", errAlreadyEnrolled
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}

	host, err := q.CreateHost(ctx, db.CreateHostParams{
		Name:        req.Hostname,
		Hostname:    req.Hostname,
		IdentityKey: req.PublicKey,
		Accounts:    tok.Accounts,
		MachineID:   machineID,
	})
	if isUniqueViolation(err) { // lost a race against a concurrent enroll
		return "", errAlreadyEnrolled
	}
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
