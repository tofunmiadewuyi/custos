package controlplane

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

// Permission catalogue: add a permission here and the can*/view/validation all follow.
var (
	allGlobalPermissions = []string{"group.create", "secret.add", "set.add"}
	allGroupPermissions  = []string{"group.read", "group.manage"}
	allHostPermissions   = []string{"host.access", "host.audit", "host.revoke", "host.upgrade"}
	allSecretPermissions = []string{"secret.read", "secret.update", "secret.delete"}
	allSetPermissions    = []string{"set.read", "set.manage"}
)

// grantablePermissions maps target_kind to its valid permissions; group carries resource perms too.
var grantablePermissions = map[string]map[string]bool{
	"global": permSet(allGlobalPermissions),
	"group":  permSet(allGroupPermissions, allHostPermissions, allSecretPermissions, allSetPermissions),
	"host":   permSet(allHostPermissions),
	"secret": permSet(allSecretPermissions),
	"set":    permSet(allSetPermissions),
}

func permSet(lists ...[]string) map[string]bool {
	set := map[string]bool{}
	for _, list := range lists {
		for _, p := range list {
			set[p] = true
		}
	}
	return set
}

// validGrant reports whether permission is grantable on the given target_kind.
func validGrant(targetKind, permission string) bool {
	return grantablePermissions[targetKind][permission]
}

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

func (s *Server) groupPermissions(ctx context.Context, a authInfo, groupID pgtype.UUID) []string {
	return filterPermissions(allGroupPermissions, func(permission string) bool {
		return s.canGroup(ctx, a, permission, groupID)
	})
}

func (s *Server) hostPermissions(ctx context.Context, a authInfo, hostID pgtype.UUID) []string {
	return filterPermissions(allHostPermissions, func(permission string) bool {
		return s.canHost(ctx, a, permission, hostID)
	})
}

func (s *Server) secretPermissions(ctx context.Context, a authInfo, secretID pgtype.UUID) []string {
	return filterPermissions(allSecretPermissions, func(permission string) bool {
		return s.canSecret(ctx, a, permission, secretID)
	})
}

func (s *Server) setPermissions(ctx context.Context, a authInfo, setID pgtype.UUID) []string {
	return filterPermissions(allSetPermissions, func(permission string) bool {
		return s.canSet(ctx, a, permission, setID)
	})
}

func filterPermissions(candidates []string, allowed func(string) bool) []string {
	permissions := make([]string, 0, len(candidates))
	for _, permission := range candidates {
		if allowed(permission) {
			permissions = append(permissions, permission)
		}
	}
	return permissions
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
