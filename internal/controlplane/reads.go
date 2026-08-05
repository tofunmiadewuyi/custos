package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

type meView struct {
	ID                string   `json:"id"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	DisplayName       string   `json:"display_name"`
	Role              string   `json:"role"`
	GlobalPermissions []string `json:"global_permissions"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	user, err := s.q.GetUserByID(r.Context(), auth.UserID)
	if err != nil {
		serverError(w, "could not load profile", err)
		return
	}
	permissions, err := s.globalPermissionsFor(r.Context(), auth)
	if err != nil {
		serverError(w, "could not load permissions", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, meView{
		ID:                uuidString(user.ID),
		Email:             user.Email,
		Name:              user.Name,
		DisplayName:       textString(user.DisplayName),
		Role:              user.Role,
		GlobalPermissions: permissions,
	})
}

func (s *Server) globalPermissionsFor(ctx context.Context, auth authInfo) ([]string, error) {
	if auth.Role == "admin" {
		rows, err := s.q.ListGlobalPermissions(ctx)
		if err != nil {
			return nil, err
		}
		permissions := make([]string, 0, len(rows))
		for _, row := range rows {
			permissions = append(permissions, row.Permission)
		}
		return permissions, nil
	}

	rows, err := s.q.ListUserGlobalPermissions(ctx, auth.UserID)
	if err != nil {
		return nil, err
	}
	permissions := make([]string, 0, len(rows))
	for _, row := range rows {
		permissions = append(permissions, row.Permission)
	}
	return permissions, nil
}

// updateProfileRequest is a partial update: nil fields are left unchanged. An
// empty display_name clears it; name cannot be emptied (it's required).
type updateProfileRequest struct {
	Name        *string `json:"name"`
	DisplayName *string `json:"display_name"`
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	var req updateProfileRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name != nil {
		if *req.Name == "" {
			http.Error(w, "name cannot be empty", http.StatusBadRequest)
			return
		}
		if err := s.q.UpdateUserName(r.Context(), db.UpdateUserNameParams{ID: auth.UserID, Name: *req.Name}); err != nil {
			serverError(w, "could not update profile", err)
			return
		}
	}
	if req.DisplayName != nil {
		if err := s.q.UpdateUserDisplayName(r.Context(), db.UpdateUserDisplayNameParams{
			ID: auth.UserID, DisplayName: pgtype.Text{String: *req.DisplayName, Valid: *req.DisplayName != ""},
		}); err != nil {
			serverError(w, "could not update profile", err)
			return
		}
	}

	user, err := s.q.GetUserByID(r.Context(), auth.UserID)
	if err != nil {
		serverError(w, "could not load profile", err)
		return
	}
	permissions, err := s.globalPermissionsFor(r.Context(), auth)
	if err != nil {
		serverError(w, "could not load permissions", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, meView{
		ID:                uuidString(user.ID),
		Email:             user.Email,
		Name:              user.Name,
		DisplayName:       textString(user.DisplayName),
		Role:              user.Role,
		GlobalPermissions: permissions,
	})
}

type hostView struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Hostname         string     `json:"hostname"`
	Accounts         []string   `json:"accounts"`
	Status           string     `json:"status"`
	ConnectionStatus string     `json:"connection_status"`
	AgentVersion     string     `json:"agent_version"`
	DesiredVersion   string     `json:"desired_version"`
	EnrolledAt       time.Time  `json:"enrolled_at"`
	LastSeenAt       *time.Time `json:"last_seen_at"`
	Permissions      []string   `json:"permissions"`
}

const hostStaleWindow = 5 * time.Minute

func (s *Server) hostConnectionStatus(id pgtype.UUID, lastSeen pgtype.Timestamptz) string {
	if s.hub.online(uuidString(id)) {
		return "online"
	}
	if !lastSeen.Valid {
		return "offline"
	}
	if time.Since(lastSeen.Time) <= hostStaleWindow {
		return "stale"
	}
	return "offline"
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	views := []hostView{}
	if auth.Role == "admin" {
		rows, err := s.q.ListHosts(r.Context())
		if err != nil {
			serverError(w, "could not list hosts", err)
			return
		}
		for _, h := range rows {
			views = append(views, hostView{
				ID: uuidString(h.ID), Name: h.Name, Hostname: h.Hostname,
				Accounts: h.Accounts, Status: h.Status,
				ConnectionStatus: s.hostConnectionStatus(h.ID, h.LastSeenAt),
				AgentVersion:     h.AgentVersion, DesiredVersion: h.DesiredVersion,
				EnrolledAt: h.EnrolledAt.Time, LastSeenAt: nullTime(h.LastSeenAt),
				Permissions: s.hostPermissions(r.Context(), auth, h.ID),
			})
		}
	} else {
		rows, err := s.q.ListReadableHosts(r.Context(), auth.UserID)
		if err != nil {
			serverError(w, "could not list hosts", err)
			return
		}
		for _, h := range rows {
			views = append(views, hostView{
				ID: uuidString(h.ID), Name: h.Name, Hostname: h.Hostname,
				Accounts: h.Accounts, Status: h.Status,
				ConnectionStatus: s.hostConnectionStatus(h.ID, h.LastSeenAt),
				AgentVersion:     h.AgentVersion, DesiredVersion: h.DesiredVersion,
				EnrolledAt: h.EnrolledAt.Time, LastSeenAt: nullTime(h.LastSeenAt),
				Permissions: s.hostPermissions(r.Context(), auth, h.ID),
			})
		}
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
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
