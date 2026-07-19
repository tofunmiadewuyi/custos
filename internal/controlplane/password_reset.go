package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/email"
	"github.com/tofunmiadewuyi/custos/internal/password"
)

const resetTTL = time.Hour

var errInvalidReset = errors.New("invalid or expired reset token")

type passwordResetRequest struct {
	Email string `json:"email"`
}

// handlePasswordReset always returns 204 whether or not the email exists, so it
// can't be used to enumerate accounts.
func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AppURL == "" {
		http.Error(w, "password reset not configured (CUSTOS_APP_URL unset)", http.StatusServiceUnavailable)
		return
	}
	var req passwordResetRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	// Run in the background so the response returns instantly whether or not the
	// email exists (no timing tell, and the email send never blocks the caller).
	go func(addr string) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.startPasswordReset(ctx, addr)
	}(req.Email)
	w.WriteHeader(http.StatusNoContent)
}

// startPasswordReset is best-effort — the client always gets 204, so the outcome
// is only visible in the server logs.
func (s *Server) startPasswordReset(ctx context.Context, addr string) {
	user, err := s.q.GetUserByEmail(ctx, addr)
	if err != nil {
		slog.Info("password reset requested for unknown email", "email", addr)
		return
	}
	raw, hash, err := GenerateToken()
	if err != nil {
		slog.Error("password reset: token generation failed", "err", err)
		return
	}
	if _, err := s.q.CreatePasswordReset(ctx, db.CreatePasswordResetParams{
		UserID: user.ID, TokenHash: hash, ExpiresAt: expiry(resetTTL),
	}); err != nil {
		slog.Error("password reset: could not store token", "err", err)
		return
	}
	link := fmt.Sprintf("%s/reset?token=%s", strings.TrimRight(s.cfg.AppURL, "/"), raw)
	if err := s.email.Send(ctx, email.Message{
		To:      addr,
		Subject: "Reset your custos password",
		HTML:    fmt.Sprintf(`<p>Reset your custos password:</p><p><a href="%s">Choose a new password</a></p><p>This link expires in an hour.</p>`, link),
	}); err != nil {
		slog.Error("password reset: email send failed", "email", addr, "err", err)
		return
	}
	slog.Info("password reset email sent", "email", addr)
}

type passwordResetConfirmRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (s *Server) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req passwordResetConfirmRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Token == "" || req.Password == "" {
		http.Error(w, "token and password are required", http.StatusBadRequest)
		return
	}

	err := s.confirmPasswordReset(r.Context(), req)
	switch {
	case errors.Is(err, errInvalidReset):
		http.Error(w, "invalid or expired reset token", http.StatusUnauthorized)
	case err != nil:
		serverError(w, "could not reset password", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// confirmPasswordReset sets the new password, consumes the token, and revokes
// all of the user's sessions so any stolen session dies with the reset.
func (s *Server) confirmPasswordReset(ctx context.Context, req passwordResetConfirmRequest) error {
	reset, err := s.q.GetPasswordReset(ctx, HashToken(req.Token))
	if errors.Is(err, pgx.ErrNoRows) {
		return errInvalidReset
	}
	if err != nil {
		return err
	}
	if reset.UsedAt.Valid || reset.ExpiresAt.Time.Before(time.Now()) {
		return errInvalidReset
	}

	hash, err := password.Hash(req.Password)
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)

	if err := q.UpdatePasswordIdentity(ctx, db.UpdatePasswordIdentityParams{
		UserID: reset.UserID, PasswordHash: pgtype.Text{String: hash, Valid: true},
	}); err != nil {
		return err
	}
	if err := q.MarkPasswordResetUsed(ctx, reset.ID); err != nil {
		return err
	}
	if err := q.RevokeAllUserSessions(ctx, reset.UserID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
