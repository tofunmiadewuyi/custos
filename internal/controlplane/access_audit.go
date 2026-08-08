package controlplane

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

type accessPath struct {
	Via        string    `json:"via"` // "direct" | "group"
	GrantID    string    `json:"grant_id"`
	Permission string    `json:"permission"`
	GroupID    string    `json:"group_id,omitempty"`
	GroupName  string    `json:"group_name,omitempty"`
	GrantedAt  time.Time `json:"granted_at"`
}

type hostAccessEntry struct {
	UserID       string       `json:"user_id"`
	Email        string       `json:"email"`
	Name         string       `json:"name"`
	DisplayName  string       `json:"display_name"`
	Role         string       `json:"role"`
	Status       string       `json:"status"`
	Fingerprints []string     `json:"fingerprints"`
	Paths        []accessPath `json:"paths"`
}

// accessEntry is one path by which a user reaches a secret. A user may appear
// more than once (e.g. a direct grant plus membership in two groups).
type accessEntry struct {
	UserID       string     `json:"user_id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	DisplayName  string     `json:"display_name"`
	Role         string     `json:"role"`
	Status       string     `json:"status"`
	Via          string     `json:"via"`                    // "direct" | "group" | "admin"
	GrantID      string     `json:"grant_id,omitempty"`     // empty for admins (no grant row)
	Permission   string     `json:"permission"`             // "*" for admins (unconditional)
	Fingerprints []string   `json:"fingerprints,omitempty"` // SSH key fingerprints for host access
	GroupID      string     `json:"group_id,omitempty"`     // set when via == "group"
	GroupName    string     `json:"group_name,omitempty"`   // set when via == "group"
	GrantedAt    *time.Time `json:"granted_at,omitempty"`   // nil for admins
}

type accessAuditView struct {
	SecretID   string        `json:"secret_id"`
	SecretName string        `json:"secret_name"`
	Entries    []accessEntry `json:"entries"`
}

// handleSecretAccessAudit (admin) reports who can reach a secret: directly, via a
// resource group, or unconditionally as an active admin (admins bypass grants, so
// omitting them would make the audit lie about who has access).
func (s *Server) handleSecretAccessAudit(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	secretID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid secret id", http.StatusBadRequest)
		return
	}

	secret, err := s.q.GetSecret(r.Context(), secretID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not load secret", err)
		return
	}

	direct, err := s.q.ListSecretDirectAccess(r.Context(), secretID)
	if err != nil {
		serverError(w, "could not load access", err)
		return
	}
	group, err := s.q.ListSecretGroupAccess(r.Context(), secretID)
	if err != nil {
		serverError(w, "could not load access", err)
		return
	}
	admins, err := s.q.ListActiveAdmins(r.Context())
	if err != nil {
		serverError(w, "could not load access", err)
		return
	}

	entries := make([]accessEntry, 0, len(direct)+len(group)+len(admins))
	for _, d := range direct {
		at := d.CreatedAt.Time
		entries = append(entries, accessEntry{
			UserID: uuidString(d.UserID), Email: d.Email, Name: d.Name,
			DisplayName: textString(d.DisplayName),
			Role:        d.Role, Status: d.Status, Via: "direct",
			GrantID:    uuidString(d.GrantID),
			Permission: d.Permission, GrantedAt: &at,
		})
	}
	for _, g := range group {
		at := g.CreatedAt.Time
		entries = append(entries, accessEntry{
			UserID: uuidString(g.UserID), Email: g.Email, Name: g.Name,
			DisplayName: textString(g.DisplayName),
			Role:        g.Role, Status: g.Status, Via: "group",
			GrantID:    uuidString(g.GrantID),
			Permission: g.Permission, GroupID: uuidString(g.GroupID),
			GroupName: g.GroupName, GrantedAt: &at,
		})
	}
	for _, a := range admins {
		entries = append(entries, accessEntry{
			UserID: uuidString(a.UserID), Email: a.Email, Name: a.Name,
			DisplayName: textString(a.DisplayName),
			Role:        "admin", Status: a.Status, Via: "admin", Permission: "*",
		})
	}

	s.writeResponse(w, auth.ClientPublicKey, accessAuditView{
		SecretID:   uuidString(secret.ID),
		SecretName: secret.Label,
		Entries:    entries,
	})
}

type hostAccessAuditView struct {
	HostID     string            `json:"host_id"`
	HostName   string            `json:"host_name"`
	Entries    []hostAccessEntry `json:"entries"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// handleHostAccessAudit reports active users with host.access, grouped by user
// so pagination never splits one user's direct/group access paths across pages.
func (s *Server) handleHostAccessAudit(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	hostID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	if !s.canHost(r.Context(), auth, "host.audit", hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	host, err := s.q.GetHostByID(r.Context(), hostID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not load host", err)
		return
	}

	limit, cur, err := userPageParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	users, err := s.q.ListHostAccessUsers(r.Context(), db.ListHostAccessUsersParams{
		HostID:      hostID,
		CursorEmail: cur.Email,
		CursorID:    cur.ID,
		PageLimit:   limit + 1,
	})
	if err != nil {
		serverError(w, "could not load access", err)
		return
	}
	var nextCursor string
	if int32(len(users)) > limit {
		last := users[limit-1]
		nextCursor = encodeUserCursor(last.Email, last.UserID)
		users = users[:limit]
	}

	entries := make([]hostAccessEntry, 0, len(users))
	byUser := map[string]int{}
	userIDs := make([]pgtype.UUID, 0, len(users))
	for _, user := range users {
		userID := uuidString(user.UserID)
		byUser[userID] = len(entries)
		userIDs = append(userIDs, user.UserID)
		entries = append(entries, hostAccessEntry{
			UserID:       userID,
			Email:        user.Email,
			Name:         user.Name,
			DisplayName:  textString(user.DisplayName),
			Role:         user.Role,
			Status:       user.Status,
			Fingerprints: user.Fingerprints,
			Paths:        []accessPath{},
		})
	}
	if len(userIDs) > 0 {
		paths, err := s.q.ListHostAccessPathsForUsers(r.Context(), db.ListHostAccessPathsForUsersParams{
			HostID: hostID, UserIds: userIDs,
		})
		if err != nil {
			serverError(w, "could not load access paths", err)
			return
		}
		for _, row := range paths {
			idx, ok := byUser[uuidString(row.UserID)]
			if !ok {
				continue
			}
			path := accessPath{
				Via:        row.Via,
				GrantID:    uuidString(row.GrantID),
				Permission: row.Permission,
				GrantedAt:  row.CreatedAt.Time,
			}
			if row.GroupID.Valid {
				path.GroupID = uuidString(row.GroupID)
				path.GroupName = row.GroupName
			}
			entries[idx].Paths = append(entries[idx].Paths, path)
		}
	}

	s.writeResponse(w, auth.ClientPublicKey, hostAccessAuditView{
		HostID:     uuidString(host.ID),
		HostName:   host.Name,
		Entries:    entries,
		NextCursor: nextCursor,
	})
}
