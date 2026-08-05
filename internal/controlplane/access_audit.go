package controlplane

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// accessEntry is one path by which a user reaches a secret. A user may appear
// more than once (e.g. a direct grant plus membership in two groups).
type accessEntry struct {
	UserID      string     `json:"user_id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	Via         string     `json:"via"`                  // "direct" | "group" | "admin"
	Permission  string     `json:"permission"`           // "*" for admins (unconditional)
	GroupID     string     `json:"group_id,omitempty"`   // set when via == "group"
	GroupName   string     `json:"group_name,omitempty"` // set when via == "group"
	GrantedAt   *time.Time `json:"granted_at,omitempty"` // nil for admins
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
			Permission: d.Permission, GrantedAt: &at,
		})
	}
	for _, g := range group {
		at := g.CreatedAt.Time
		entries = append(entries, accessEntry{
			UserID: uuidString(g.UserID), Email: g.Email, Name: g.Name,
			DisplayName: textString(g.DisplayName),
			Role:        g.Role, Status: g.Status, Via: "group",
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
	HostID   string        `json:"host_id"`
	HostName string        `json:"host_name"`
	Entries  []accessEntry `json:"entries"`
}

// handleHostAccessAudit reports who can SSH to a host: directly, via a group the
// host belongs to, or unconditionally as an active admin.
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

	direct, err := s.q.ListHostDirectAccess(r.Context(), hostID)
	if err != nil {
		serverError(w, "could not load access", err)
		return
	}
	group, err := s.q.ListHostGroupAccess(r.Context(), hostID)
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
			Permission: d.Permission, GrantedAt: &at,
		})
	}
	for _, g := range group {
		at := g.CreatedAt.Time
		entries = append(entries, accessEntry{
			UserID: uuidString(g.UserID), Email: g.Email, Name: g.Name,
			DisplayName: textString(g.DisplayName),
			Role:        g.Role, Status: g.Status, Via: "group",
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

	s.writeResponse(w, auth.ClientPublicKey, hostAccessAuditView{
		HostID:   uuidString(host.ID),
		HostName: host.Name,
		Entries:  entries,
	})
}
