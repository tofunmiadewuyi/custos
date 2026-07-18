package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Protected routes must reject requests without a bearer token before any DB
// access, so this runs with a nil pool.
func TestProtectedRoutesRejectUnauthenticated(t *testing.T) {
	s := NewServer(Config{}, nil)
	for _, path := range []string{"/logout", "/keys", "/secrets", "/enroll-tokens", "/grants", "/invitations", "/groups"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth: got %d, want 401", path, rec.Code)
		}
	}
}
