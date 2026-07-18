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
