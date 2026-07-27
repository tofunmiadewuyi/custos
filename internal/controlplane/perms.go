package controlplane

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

// canGlobal reports whether the user may perform a global-scoped action.
// Admins bypass grants entirely.
func (s *Server) canGlobal(ctx context.Context, a authInfo, permission string) bool {
	if a.Role == "admin" {
		return true
	}
	ok, err := s.q.UserHasGlobalPermission(ctx, db.UserHasGlobalPermissionParams{
		UserID: a.UserID, Permission: permission,
	})
	return err == nil && ok
}

// canSecret reports whether the user holds permission on a specific secret,
// directly or via a group. Admins bypass grants.
func (s *Server) canSecret(ctx context.Context, a authInfo, permission string, secretID pgtype.UUID) bool {
	if a.Role == "admin" {
		return true
	}
	ok, err := s.q.UserHasSecretPermission(ctx, db.UserHasSecretPermissionParams{
		UserID: a.UserID, Permission: permission, SecretID: secretID,
	})
	return err == nil && ok
}

// canHost reports whether the user holds permission on a specific host, directly
// or via a group. Admins bypass grants.
func (s *Server) canHost(ctx context.Context, a authInfo, permission string, hostID pgtype.UUID) bool {
	if a.Role == "admin" {
		return true
	}
	ok, err := s.q.UserHasHostPermission(ctx, db.UserHasHostPermissionParams{
		UserID: a.UserID, Permission: permission, HostID: hostID,
	})
	return err == nil && ok
}

// canGroup reports whether the user holds permission on a specific group. Admins bypass.
func (s *Server) canGroup(ctx context.Context, a authInfo, permission string, groupID pgtype.UUID) bool {
	if a.Role == "admin" {
		return true
	}
	ok, err := s.q.UserHasGroupPermission(ctx, db.UserHasGroupPermissionParams{
		UserID: a.UserID, Permission: permission, GroupID: groupID,
	})
	return err == nil && ok
}

// canSet reports whether the user holds permission on a specific set. Admins bypass.
func (s *Server) canSet(ctx context.Context, a authInfo, permission string, setID pgtype.UUID) bool {
	if a.Role == "admin" {
		return true
	}
	ok, err := s.q.UserHasSetPermission(ctx, db.UserHasSetPermissionParams{
		UserID: a.UserID, Permission: permission, SetID: setID,
	})
	return err == nil && ok
}
