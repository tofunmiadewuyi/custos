package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthz(t *testing.T) {
	s := NewServer(Config{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

// TestRoutesResolve checks the registered routes match (no bearer token => 401,
// never 404). It guards the r.Route grouping, especially collection Get("/").
func TestRoutesResolve(t *testing.T) {
	s := NewServer(Config{}, nil)
	h := s.Handler()
	cases := []struct{ method, path string }{
		{"GET", "/keys"}, {"DELETE", "/keys/x"},
		{"GET", "/secrets"}, {"GET", "/secrets/x/audit"},
		{"GET", "/groups"}, {"GET", "/groups/x/members"}, {"PUT", "/groups/x"}, {"POST", "/groups/x/resources"},
		{"GET", "/sets"}, {"PUT", "/sets/x/entries/KEY"},
		{"POST", "/hosts/x/sets"}, {"GET", "/hosts/x"}, {"GET", "/hosts/x/audit"},
		{"GET", "/users"}, {"POST", "/users/x/suspend"},
		{"GET", "/grants"}, {"GET", "/invitations"},
		{"GET", "/hosts"}, {"GET", "/secrets/x/access-audit"}, {"GET", "/hosts/x/access-audit"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s did not resolve (404)", c.method, c.path)
		}
	}
}

func TestEnrollRejectsBadRequest(t *testing.T) {
	s := NewServer(Config{}, nil)
	cases := map[string]string{
		"invalid json":   "{not json",
		"missing fields": `{"hostname":"h"}`,
	}
	for name, body := range cases {
		req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
	}
}
