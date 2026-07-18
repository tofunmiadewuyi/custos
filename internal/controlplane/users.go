package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

type userView struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.q.ListUsers(r.Context())
	if err != nil {
		serverError(w, "could not list users", err)
		return
	}
	views := make([]userView, 0, len(rows))
	for _, u := range rows {
		views = append(views, userView{uuidString(u.ID), u.Email, u.Name, u.Role, u.Status, u.CreatedAt.Time})
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, views)
}

func (s *Server) handleSuspendUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.targetUser(w, r)
	if !ok {
		return
	}
	// Grants stay intact (suspend is reversible); the snapshot filters by status.
	hosts, _ := s.q.UserGrantedHostIDs(r.Context(), userID)

	n, err := s.q.SetUserStatus(r.Context(), db.SetUserStatusParams{ID: userID, Status: "suspended"})
	if err != nil {
		serverError(w, "could not suspend user", err)
		return
	}
	if n == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	s.q.RevokeAllUserSessions(r.Context(), userID)
	s.pushToHosts(r.Context(), hosts)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleActivateUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.targetUser(w, r)
	if !ok {
		return
	}
	n, err := s.q.SetUserStatus(r.Context(), db.SetUserStatusParams{ID: userID, Status: "active"})
	if err != nil {
		serverError(w, "could not activate user", err)
		return
	}
	if n == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	hosts, _ := s.q.UserGrantedHostIDs(r.Context(), userID)
	s.pushToHosts(r.Context(), hosts)
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveUser permanently blocks a user: their login identities and grants
// go away, but the user row, keys, and logs remain so history stays attributable.
func (s *Server) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.targetUser(w, r)
	if !ok {
		return
	}
	hosts, _ := s.q.UserGrantedHostIDs(r.Context(), userID) // before grants are revoked

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not remove user", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	n, err := q.SetUserStatus(r.Context(), db.SetUserStatusParams{ID: userID, Status: "removed"})
	if err != nil {
		serverError(w, "could not remove user", err)
		return
	}
	if n == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if err := q.DeleteUserIdentities(r.Context(), userID); err != nil {
		serverError(w, "could not remove user", err)
		return
	}
	if err := q.RevokeAllUserGrants(r.Context(), userID); err != nil {
		serverError(w, "could not remove user", err)
		return
	}
	if err := q.RevokeAllUserSessions(r.Context(), userID); err != nil {
		serverError(w, "could not remove user", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not remove user", err)
		return
	}

	s.pushToHosts(r.Context(), hosts)
	w.WriteHeader(http.StatusNoContent)
}

// targetUser parses the {id} param and refuses self-targeting, so an admin can't
// suspend or remove their own account.
func (s *Server) targetUser(w http.ResponseWriter, r *http.Request) (pgtype.UUID, bool) {
	userID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return pgtype.UUID{}, false
	}
	if uuidString(userID) == uuidString(authFrom(r.Context()).UserID) {
		http.Error(w, "you cannot change your own account status", http.StatusBadRequest)
		return pgtype.UUID{}, false
	}
	return userID, true
}

func (s *Server) pushToHosts(ctx context.Context, hosts []pgtype.UUID) {
	for _, h := range hosts {
		s.pushSnapshot(ctx, h)
	}
}
