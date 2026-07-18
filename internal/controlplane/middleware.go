package controlplane

import (
	"context"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
)

type ctxKey int

const authKey ctxKey = iota

type authInfo struct {
	SessionID       pgtype.UUID
	UserID          pgtype.UUID
	Role            string
	ClientPublicKey []byte
}

func authFrom(ctx context.Context) authInfo {
	a, _ := ctx.Value(authKey).(authInfo)
	return a
}

// requireAuth resolves the bearer access token to a session on every request,
// so a revoked session is rejected immediately.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		row, err := s.q.GetAccessContext(r.Context(), HashToken(token))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if row.Status != "active" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), authKey, authInfo{
			SessionID:       row.SessionID,
			UserID:          row.UserID,
			Role:            row.Role,
			ClientPublicKey: row.ClientPublicKey,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authFrom(r.Context()).Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func bearerToken(r *http.Request) string {
	if after, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}
