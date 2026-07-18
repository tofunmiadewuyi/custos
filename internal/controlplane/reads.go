package controlplane

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type meView struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	user, err := s.q.GetUserByID(r.Context(), auth.UserID)
	if err != nil {
		serverError(w, "could not load profile", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, meView{
		ID:    uuidString(user.ID),
		Email: user.Email,
		Name:  user.Name,
		Role:  user.Role,
	})
}

type hostView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Hostname   string     `json:"hostname"`
	Accounts   []string   `json:"accounts"`
	Status     string     `json:"status"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	LastSeenAt *time.Time `json:"last_seen_at"`
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.q.ListHosts(r.Context())
	if err != nil {
		serverError(w, "could not list hosts", err)
		return
	}
	views := make([]hostView, 0, len(rows))
	for _, h := range rows {
		views = append(views, hostView{
			ID:         uuidString(h.ID),
			Name:       h.Name,
			Hostname:   h.Hostname,
			Accounts:   h.Accounts,
			Status:     h.Status,
			EnrolledAt: h.EnrolledAt.Time,
			LastSeenAt: nullTime(h.LastSeenAt),
		})
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, views)
}

type grantView struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	UserEmail  string    `json:"user_email"`
	Permission string    `json:"permission"`
	TargetKind string    `json:"target_kind"`
	TargetID   string    `json:"target_id"` // empty for global
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	rows, err := s.q.ListGrants(r.Context())
	if err != nil {
		serverError(w, "could not list grants", err)
		return
	}
	views := make([]grantView, 0, len(rows))
	for _, g := range rows {
		views = append(views, grantView{
			ID:         uuidString(g.ID),
			UserID:     uuidString(g.UserID),
			UserEmail:  g.UserEmail,
			Permission: g.Permission,
			TargetKind: g.TargetKind,
			TargetID:   uuidString(g.TargetID),
			CreatedAt:  g.CreatedAt.Time,
		})
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, views)
}

func nullTime(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}
