package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/email"
	"github.com/tofunmiadewuyi/custos/internal/password"
)

const inviteTTL = 7 * 24 * time.Hour

var errInvalidInvite = errors.New("invalid or expired invitation")

type createInvitationRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type invitationView struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AppURL == "" {
		http.Error(w, "invites not configured (CUSTOS_APP_URL unset)", http.StatusServiceUnavailable)
		return
	}
	var req createInvitationRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	role := req.Role
	if role == "" {
		role = "member"
	}
	if role != "admin" && role != "member" {
		http.Error(w, "role must be admin or member", http.StatusBadRequest)
		return
	}

	auth := authFrom(r.Context())
	raw, hash, err := GenerateToken()
	if err != nil {
		serverError(w, "could not create invitation", err)
		return
	}
	inv, err := s.q.CreateInvitation(r.Context(), db.CreateInvitationParams{
		Email:     req.Email,
		Role:      role,
		TokenHash: hash,
		InvitedBy: auth.UserID,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(inviteTTL), Valid: true},
	})
	if err != nil {
		serverError(w, "could not create invitation", err)
		return
	}

	if err := s.sendInvite(r.Context(), req.Email, raw); err != nil {
		serverError(w, "invitation created but email failed to send", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, invitationView{
		ID: uuidString(inv.ID), Email: inv.Email, Role: inv.Role, ExpiresAt: inv.ExpiresAt.Time,
	})
}

func (s *Server) sendInvite(ctx context.Context, to, token string) error {
	link := fmt.Sprintf("%s/accept?token=%s", strings.TrimRight(s.cfg.AppURL, "/"), token)
	return s.email.Send(ctx, email.Message{
		To:      to,
		Subject: "You're invited to custos",
		HTML:    fmt.Sprintf(`<p>You've been invited to custos.</p><p><a href="%s">Accept your invitation</a></p>`, link),
	})
}

type acceptInvitationRequest struct {
	Token       string `json:"token"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

func (s *Server) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req acceptInvitationRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Token == "" || req.Name == "" || req.Password == "" {
		http.Error(w, "token, name and password are required", http.StatusBadRequest)
		return
	}

	err := s.acceptInvitation(r.Context(), req)
	switch {
	case errors.Is(err, errInvalidInvite):
		http.Error(w, "invalid or expired invitation", http.StatusUnauthorized)
	case errors.Is(err, ErrEmailTaken):
		http.Error(w, "an account with that email already exists", http.StatusConflict)
	case err != nil:
		serverError(w, "could not accept invitation", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) acceptInvitation(ctx context.Context, req acceptInvitationRequest) error {
	inv, err := s.q.GetInvitationByTokenHash(ctx, HashToken(req.Token))
	if errors.Is(err, pgx.ErrNoRows) {
		return errInvalidInvite
	}
	if err != nil {
		return err
	}
	if inv.AcceptedAt.Valid || inv.ExpiresAt.Time.Before(time.Now()) {
		return errInvalidInvite
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

	user, err := q.CreateUser(ctx, db.CreateUserParams{
		Email:       inv.Email,
		Name:        req.Name,
		DisplayName: pgtype.Text{String: req.DisplayName, Valid: req.DisplayName != ""},
		Role:        inv.Role,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return ErrEmailTaken
		}
		return err
	}
	if _, err := q.CreateIdentity(ctx, db.CreateIdentityParams{
		UserID:       user.ID,
		Provider:     "password",
		ExternalID:   inv.Email,
		PasswordHash: pgtype.Text{String: hash, Valid: true},
	}); err != nil {
		return err
	}
	if err := q.MarkInvitationAccepted(ctx, inv.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) handleCancelInvitation(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid invitation id", http.StatusBadRequest)
		return
	}
	n, err := s.q.DeleteInvitation(r.Context(), id)
	if err != nil {
		serverError(w, "could not cancel invitation", err)
		return
	}
	if n == 0 {
		http.Error(w, "invitation not found or already accepted", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleResendInvitation rotates the token (we only stored a hash), extends the
// expiry, and re-emails the new link. The previous link stops working.
func (s *Server) handleResendInvitation(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AppURL == "" {
		http.Error(w, "invites not configured (CUSTOS_APP_URL unset)", http.StatusServiceUnavailable)
		return
	}
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid invitation id", http.StatusBadRequest)
		return
	}
	raw, hash, err := GenerateToken()
	if err != nil {
		serverError(w, "could not resend invitation", err)
		return
	}
	inv, err := s.q.RefreshInvitationToken(r.Context(), db.RefreshInvitationTokenParams{
		ID: id, TokenHash: hash, ExpiresAt: expiry(inviteTTL),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "invitation not found or already accepted", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not resend invitation", err)
		return
	}
	if err := s.sendInvite(r.Context(), inv.Email, raw); err != nil {
		serverError(w, "invitation updated but email failed to send", err)
		return
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, invitationView{
		ID: uuidString(inv.ID), Email: inv.Email, Role: inv.Role, ExpiresAt: inv.ExpiresAt.Time,
	})
}

func (s *Server) handleListInvitations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.q.ListPendingInvitations(r.Context())
	if err != nil {
		serverError(w, "could not list invitations", err)
		return
	}
	views := make([]invitationView, 0, len(rows))
	for _, inv := range rows {
		views = append(views, invitationView{
			ID: uuidString(inv.ID), Email: inv.Email, Role: inv.Role, ExpiresAt: inv.ExpiresAt.Time,
		})
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, views)
}
