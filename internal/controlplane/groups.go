package controlplane

import (
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

type groupView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type groupResourceView struct {
	ResourceKind string    `json:"resource_kind"`
	ResourceID   string    `json:"resource_id"`
	AddedAt      time.Time `json:"added_at"`
}

type groupDetailView struct {
	groupView
	Resources []groupResourceView `json:"resources"`
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req createGroupRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	g, err := s.q.CreateGroup(r.Context(), db.CreateGroupParams{Name: req.Name, Description: req.Description})
	if err != nil {
		serverError(w, "could not create group", err)
		return
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, toGroupView(g))
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := s.q.ListGroups(r.Context())
	if err != nil {
		serverError(w, "could not list groups", err)
		return
	}
	views := make([]groupView, 0, len(rows))
	for _, g := range rows {
		views = append(views, groupView{uuidString(g.ID), g.Name, g.Description, g.CreatedAt.Time})
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, views)
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
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
		resources = append(resources, groupResourceView{m.ResourceKind, uuidString(m.ResourceID), m.AddedAt.Time})
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, groupDetailView{toGroupView(g), resources})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
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
	var req struct {
		ResourceKind string `json:"resource_kind"`
		ResourceID   string `json:"resource_id"`
	}
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.ResourceKind != "host" && req.ResourceKind != "secret" {
		http.Error(w, "resource_kind must be host or secret", http.StatusBadRequest)
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
	var req struct {
		ResourceKind string `json:"resource_kind"`
		ResourceID   string `json:"resource_id"`
	}
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
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

func toGroupView(g db.ResourceGroup) groupView {
	return groupView{uuidString(g.ID), g.Name, g.Description, g.CreatedAt.Time}
}
