//go:build integration

package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/tofunmiadewuyi/custos/migrations"
)

// newTestServer spins an ephemeral Postgres in Docker, migrates it, and returns a
// Server plus a bearer token for a seeded admin. All torn down on cleanup — the
// test brings its own database and needs nothing pre-existing but a Docker daemon.
func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	ctx := context.Background()

	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("custos"),
		postgres.WithUsername("custos"),
		postgres.WithPassword("custos"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { pg.Terminate(ctx) })

	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	runMigrations(t, url)

	pool, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// Zero master key is a valid AES-256 key — fine for a test wrapper; encryption
	// off so handlers read/write plain JSON.
	s := NewServer(Config{MasterKey: make([]byte, 32), EncryptionEnabled: false}, pool)
	return s, seedAdmin(t, pool)
}

func runMigrations(t *testing.T, url string) {
	t.Helper()
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.RunContext(context.Background(), "up", db, "."); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// seedAdmin inserts an active admin with a live session + access token, returning the bearer token.
func seedAdmin(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var userID, sessionID string
	if err := pool.QueryRow(ctx,
		`insert into users (email, name, role, status) values ('admin@test', 'Admin', 'admin', 'active') returning id`,
	).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`insert into sessions (user_id, token_hash, expires_at) values ($1, 'sess-hash', now() + interval '1 hour') returning id`,
		userID,
	).Scan(&sessionID); err != nil {
		t.Fatal(err)
	}
	token := "test-admin-token"
	if _, err := pool.Exec(ctx,
		`insert into access_tokens (session_id, token_hash, expires_at) values ($1, $2, now() + interval '1 hour')`,
		sessionID, HashToken(token),
	); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestSetLifecycle(t *testing.T) {
	s, token := newTestServer(t)
	h := s.Handler()

	body := `{"name":"billing","entries":[{"key":"DB_URL","value":"postgres://x"},{"key":"MASTER_KEY","value":"s3cr3t"}]}`
	rec := do(t, h, token, "POST", "/sets", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("create set: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID   string   `json:"id"`
		Name string   `json:"name"`
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "billing" || len(created.Keys) != 2 {
		t.Fatalf("unexpected create response: %s", rec.Body.String())
	}

	// The creator (admin) can read it back, and the audit shows the create.
	if rec := do(t, h, token, "GET", "/sets/"+created.ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("get set: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, token, "GET", "/sets/"+created.ID+"/audit", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"action":"create"`) {
		t.Fatalf("expected a create audit row, got %d %s", rec.Code, rec.Body.String())
	}
}

func do(t *testing.T, h http.Handler, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
