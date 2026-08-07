package controlplane

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

type createGrantRequest struct {
	UserID     string `json:"user_id"`
	Permission string `json:"permission"`
	TargetKind string `json:"target_kind"`
	TargetID   string `json:"target_id"` // omit for global grants
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	var req createGrantRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.UserID == "" || req.Permission == "" || req.TargetKind == "" {
		http.Error(w, "user_id, permission and target_kind are required", http.StatusBadRequest)
		return
	}
	if !validGrant(req.TargetKind, req.Permission) {
		http.Error(w, "invalid permission for target_kind", http.StatusBadRequest)
		return
	}
	userID, err := parseUUID(req.UserID)
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}
	var targetID pgtype.UUID
	if req.TargetKind != "global" {
		if targetID, err = parseUUID(req.TargetID); err != nil {
			http.Error(w, "invalid target_id", http.StatusBadRequest)
			return
		}
	}

	auth := authFrom(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not create grant", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	grant, err := q.CreateGrant(r.Context(), db.CreateGrantParams{
		UserID:     userID,
		Permission: req.Permission,
		TargetKind: req.TargetKind,
		TargetID:   targetID,
		GrantedBy:  auth.UserID,
	})
	if err != nil {
		http.Error(w, "could not create grant", http.StatusBadRequest)
		return
	}
	if err := s.auditGrant(r.Context(), q, "grant", grant, auth.UserID); err != nil {
		serverError(w, "could not record grant", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not create grant", err)
		return
	}
	s.pushIfHostGrant(r.Context(), grant.Permission, grant.TargetKind, grant.TargetID)
	s.writeResponse(w, auth.ClientPublicKey, map[string]string{"id": uuidString(grant.ID)})
}

// grantOwner gives the creator full scoped access to a resource they just made,
// so members own what they create. Runs inside the create tx; self-granted.
func (s *Server) grantOwner(ctx context.Context, q *db.Queries, userID pgtype.UUID, kind string, targetID pgtype.UUID, perms ...string) error {
	for _, p := range perms {
		if _, err := q.CreateGrant(ctx, db.CreateGrantParams{
			UserID: userID, Permission: p, TargetKind: kind, TargetID: targetID, GrantedBy: userID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	grantID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid grant id", http.StatusBadRequest)
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		serverError(w, "could not revoke grant", err)
		return
	}
	defer tx.Rollback(r.Context())
	q := db.New(tx)

	grant, err := q.RevokeGrant(r.Context(), grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "grant not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not revoke grant", err)
		return
	}
	if err := s.auditGrant(r.Context(), q, "revoke", grant, authFrom(r.Context()).UserID); err != nil {
		serverError(w, "could not record revoke", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		serverError(w, "could not revoke grant", err)
		return
	}
	s.pushIfHostGrant(r.Context(), grant.Permission, grant.TargetKind, grant.TargetID)
	w.WriteHeader(http.StatusNoContent)
}

// auditGrant writes the audit row in the caller's tx, so grant and audit commit or roll back together.
func (s *Server) auditGrant(ctx context.Context, q *db.Queries, action string, grant db.Grant, actorID pgtype.UUID) error {
	return q.InsertGrantAudit(ctx, db.InsertGrantAuditParams{
		Action:       action,
		GrantID:      grant.ID,
		ActorID:      actorID,
		ActorEmail:   s.emailOf(ctx, actorID),
		SubjectID:    grant.UserID,
		SubjectEmail: s.emailOf(ctx, grant.UserID),
		Permission:   grant.Permission,
		TargetKind:   grant.TargetKind,
		TargetID:     grant.TargetID,
	})
}

// emailOf best-effort resolves a user's email for audit denormalization.
func (s *Server) emailOf(ctx context.Context, id pgtype.UUID) string {
	if u, err := s.q.GetUserByID(ctx, id); err == nil {
		return u.Email
	}
	return ""
}

// pushIfHostGrant pushes a fresh snapshot to every affected host when a
// host.access grant changes, so grant/revoke takes effect immediately.
func (s *Server) pushIfHostGrant(ctx context.Context, permission, targetKind string, targetID pgtype.UUID) {
	if permission != "host.access" {
		return
	}
	var hosts []pgtype.UUID
	switch targetKind {
	case "host":
		hosts = []pgtype.UUID{targetID}
	case "group":
		ids, err := s.q.GroupHostIDs(ctx, targetID)
		if err != nil {
			return
		}
		hosts = ids
	default:
		return
	}
	for _, h := range hosts {
		s.pushSnapshot(ctx, h)
	}
}

func (s *Server) pushSnapshot(ctx context.Context, hostID pgtype.UUID) {
	host, err := s.q.GetHostByID(ctx, hostID)
	if err != nil {
		return
	}
	snapshot, err := s.buildSnapshot(ctx, host)
	if err != nil {
		return
	}
	env, err := s.snapshotEnvelope(ctx, hostID, snapshot)
	if err != nil {
		return
	}
	s.hub.push(uuidString(hostID), env)
}
