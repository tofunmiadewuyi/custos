package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

type createGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type updateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type groupView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	Permissions []string  `json:"permissions"`
}

type groupResourceView struct {
	ResourceKind string       `json:"resource_kind"`
	ResourceID   string       `json:"resource_id"`
	AddedAt      time.Time    `json:"added_at"`
	DisplayName  string       `json:"display_name,omitempty"`
	Host         *hostView    `json:"host,omitempty"`
	Secret       *secretView  `json:"secret,omitempty"`
	Set          *setListView `json:"set,omitempty"`
}

type groupDetailView struct {
	groupView
	Resources []groupResourceView `json:"resources"`
}

type groupMemberGrantView struct {
	ID         string    `json:"id"`
	Permission string    `json:"permission"`
	GrantedAt  time.Time `json:"granted_at"`
}

type groupMemberView struct {
	UserID      string                 `json:"user_id"`
	Email       string                 `json:"email"`
	Name        string                 `json:"name"`
	DisplayName string                 `json:"display_name"`
	Role        string                 `json:"role"`
	Status      string                 `json:"status"`
	Permissions []string               `json:"permissions"`
	Grants      []groupMemberGrantView `json:"grants"`
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	if !s.canGlobal(r.Context(), auth, "group.create") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req createGroupRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not create group", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	g, err := q.CreateGroup(r.Context(), db.CreateGroupParams{Name: req.Name, Description: req.Description})
	if err != nil {
		serverError(w, "could not create group", err)
		return
	}
	if err := s.grantOwner(r.Context(), q, auth.UserID, "group", g.ID, "group.read", "group.manage"); err != nil {
		serverError(w, "could not create group", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not create group", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, s.toGroupView(r.Context(), auth, g))
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	views := []groupView{}
	if auth.Role == "admin" {
		rows, err := s.q.ListGroups(r.Context())
		if err != nil {
			serverError(w, "could not list groups", err)
			return
		}
		for _, g := range rows {
			views = append(views, s.toGroupView(r.Context(), auth, g))
		}
	} else {
		rows, err := s.q.ListReadableGroups(r.Context(), auth.UserID)
		if err != nil {
			serverError(w, "could not list groups", err)
			return
		}
		for _, g := range rows {
			views = append(views, s.toGroupView(r.Context(), auth, g))
		}
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

func (s *Server) handleListGroupsForResource(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	resourceKind := chi.URLParam(r, "kind")
	if resourceKind != "host" && resourceKind != "secret" && resourceKind != "set" {
		http.Error(w, "resource kind must be host, secret or set", http.StatusBadRequest)
		return
	}
	resourceID, err := parseUUID(chi.URLParam(r, "resourceID"))
	if err != nil {
		http.Error(w, "invalid resource id", http.StatusBadRequest)
		return
	}
	views := []groupView{}
	if auth.Role == "admin" {
		rows, err := s.q.ListGroupsForResource(r.Context(), db.ListGroupsForResourceParams{
			ResourceKind: resourceKind, ResourceID: resourceID,
		})
		if err != nil {
			serverError(w, "could not list resource groups", err)
			return
		}
		for _, g := range rows {
			views = append(views, s.toGroupView(r.Context(), auth, g))
		}
	} else {
		rows, err := s.q.ListReadableGroupsForResource(r.Context(), db.ListReadableGroupsForResourceParams{
			UserID: auth.UserID, ResourceKind: resourceKind, ResourceID: resourceID,
		})
		if err != nil {
			serverError(w, "could not list resource groups", err)
			return
		}
		for _, g := range rows {
			views = append(views, s.toGroupView(r.Context(), auth, g))
		}
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

func (s *Server) handleListGroupMembers(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if !s.canGroup(r.Context(), auth, "group.read", groupID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := s.q.GetGroup(r.Context(), groupID); errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	} else if err != nil {
		serverError(w, "could not load group", err)
		return
	}
	rows, err := s.q.ListGroupMembers(r.Context(), groupID)
	if err != nil {
		serverError(w, "could not list group members", err)
		return
	}
	members := []groupMemberView{}
	byUser := map[string]int{}
	for _, row := range rows {
		userID := uuidString(row.UserID)
		idx, ok := byUser[userID]
		if !ok {
			idx = len(members)
			byUser[userID] = idx
			members = append(members, groupMemberView{
				UserID:      userID,
				Email:       row.Email,
				Name:        row.Name,
				DisplayName: textString(row.DisplayName),
				Role:        row.Role,
				Status:      row.Status,
				Permissions: []string{},
				Grants:      []groupMemberGrantView{},
			})
		}
		members[idx].Permissions = append(members[idx].Permissions, row.Permission)
		members[idx].Grants = append(members[idx].Grants, groupMemberGrantView{
			ID: uuidString(row.GrantID), Permission: row.Permission, GrantedAt: row.GrantedAt.Time,
		})
	}
	s.writeResponse(w, auth.ClientPublicKey, members)
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if !s.canGroup(r.Context(), auth, "group.read", groupID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	g, err := s.q.GetGroup(r.Context(), groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not load group", err)
		return
	}
	rows, err := s.q.ListGroupResources(r.Context(), groupID)
	if err != nil {
		serverError(w, "could not load group", err)
		return
	}
	resources := make([]groupResourceView, 0, len(rows))
	for _, m := range rows {
		resources = append(resources, s.toGroupResourceView(r.Context(), auth, m))
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, groupDetailView{s.toGroupView(r.Context(), auth, g), resources})
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if !s.canGroup(r.Context(), auth, "group.manage", groupID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req updateGroupRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	g, err := s.q.UpdateGroup(r.Context(), db.UpdateGroupParams{
		ID: groupID, Name: req.Name, Description: req.Description,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not update group", err)
		return
	}
	s.writeResponse(w, auth.ClientPublicKey, s.toGroupView(r.Context(), auth, g))
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if !s.canGroup(r.Context(), authFrom(r.Context()), "group.manage", groupID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Member hosts, grabbed before deletion so we can push their new snapshots.
	hosts, _ := s.q.GroupHostIDs(r.Context(), groupID)

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not delete group", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	if err := q.RevokeGroupGrants(r.Context(), groupID); err != nil {
		serverError(w, "could not delete group", err)
		return
	}
	n, err := q.DeleteGroup(r.Context(), groupID)
	if err != nil {
		serverError(w, "could not delete group", err)
		return
	}
	if n == 0 {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not delete group", err)
		return
	}

	for _, h := range hosts {
		s.pushSnapshot(r.Context(), h)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddGroupResource(w http.ResponseWriter, r *http.Request) {
	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if !s.canGroup(r.Context(), authFrom(r.Context()), "group.manage", groupID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		ResourceKind string `json:"resource_kind"`
		ResourceID   string `json:"resource_id"`
	}
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.ResourceKind != "host" && req.ResourceKind != "secret" && req.ResourceKind != "set" {
		http.Error(w, "resource_kind must be host, secret or set", http.StatusBadRequest)
		return
	}
	resourceID, err := parseUUID(req.ResourceID)
	if err != nil {
		http.Error(w, "invalid resource_id", http.StatusBadRequest)
		return
	}
	if err := s.q.AddGroupResource(r.Context(), db.AddGroupResourceParams{
		GroupID: groupID, ResourceKind: req.ResourceKind, ResourceID: resourceID,
	}); err != nil {
		serverError(w, "could not add resource", err)
		return
	}
	if req.ResourceKind == "host" {
		s.pushSnapshot(r.Context(), resourceID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveGroupResource(w http.ResponseWriter, r *http.Request) {
	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if !s.canGroup(r.Context(), authFrom(r.Context()), "group.manage", groupID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		ResourceKind string `json:"resource_kind"`
		ResourceID   string `json:"resource_id"`
	}
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.ResourceKind != "host" && req.ResourceKind != "secret" && req.ResourceKind != "set" {
		http.Error(w, "resource_kind must be host, secret or set", http.StatusBadRequest)
		return
	}
	resourceID, err := parseUUID(req.ResourceID)
	if err != nil {
		http.Error(w, "invalid resource_id", http.StatusBadRequest)
		return
	}
	n, err := s.q.RemoveGroupResource(r.Context(), db.RemoveGroupResourceParams{
		GroupID: groupID, ResourceKind: req.ResourceKind, ResourceID: resourceID,
	})
	if err != nil {
		serverError(w, "could not remove resource", err)
		return
	}
	if n == 0 {
		http.Error(w, "resource not in group", http.StatusNotFound)
		return
	}
	if req.ResourceKind == "host" {
		s.pushSnapshot(r.Context(), resourceID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) toGroupView(ctx context.Context, auth authInfo, g db.ResourceGroup) groupView {
	return groupView{
		ID:          uuidString(g.ID),
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   g.CreatedAt.Time,
		Permissions: s.groupPermissions(ctx, auth, g.ID),
	}
}

func (s *Server) toGroupResourceView(ctx context.Context, auth authInfo, row db.ListGroupResourcesRow) groupResourceView {
	view := groupResourceView{
		ResourceKind: row.ResourceKind,
		ResourceID:   uuidString(row.ResourceID),
		AddedAt:      row.AddedAt.Time,
	}
	switch row.ResourceKind {
	case "host":
		if row.HostID.Valid {
			view.DisplayName = row.HostName
			view.Host = &hostView{
				ID:               uuidString(row.HostID),
				Name:             row.HostName,
				Hostname:         row.HostHostname,
				Accounts:         row.HostAccounts,
				Status:           row.HostStatus,
				ConnectionStatus: s.hostConnectionStatus(row.HostID, row.HostLastSeenAt),
				AgentVersion:     row.HostAgentVersion,
				DesiredVersion:   row.HostDesiredVersion,
				EnrolledAt:       row.HostEnrolledAt.Time,
				LastSeenAt:       nullTime(row.HostLastSeenAt),
				Permissions:      s.hostPermissions(ctx, auth, row.HostID),
			}
		}
	case "secret":
		if row.SecretID.Valid {
			view.DisplayName = row.SecretLabel
			view.Secret = &secretView{
				ID:           uuidString(row.SecretID),
				Label:        row.SecretLabel,
				URL:          textString(row.SecretUrl),
				Username:     textString(row.SecretUsername),
				OTPRecipient: textString(row.SecretOtpRecipient),
				CreatedAt:    row.SecretCreatedAt.Time,
				UpdatedAt:    row.SecretUpdatedAt.Time,
				Permissions:  s.secretPermissions(ctx, auth, row.SecretID),
			}
		}
	case "set":
		if row.SetID.Valid {
			view.DisplayName = row.SetName
			view.Set = &setListView{
				ID:          uuidString(row.SetID),
				Name:        row.SetName,
				KeyCount:    row.SetKeyCount,
				CreatedAt:   row.SetCreatedAt.Time,
				UpdatedAt:   row.SetUpdatedAt.Time,
				Permissions: s.setPermissions(ctx, auth, row.SetID),
			}
		}
	}
	return view
}
