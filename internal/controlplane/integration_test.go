//go:build integration

package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/hybrid"
	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
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
	_, adminToken := seedUser(t, pool, "admin@test", "admin")
	return s, adminToken
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

// seedUser inserts an active user with a live session + access token, returning
// its id and a bearer token.
func seedUser(t *testing.T, pool *pgxpool.Pool, email, role string) (userID, token string) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`insert into users (email, name, role, status) values ($1, $1, $2, 'active') returning id`,
		email, role,
	).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	var sessionID string
	if err := pool.QueryRow(ctx,
		`insert into sessions (user_id, token_hash, expires_at) values ($1, $2, now() + interval '1 hour') returning id`,
		userID, "sess-"+email,
	).Scan(&sessionID); err != nil {
		t.Fatal(err)
	}
	token = "tok-" + email
	if _, err := pool.Exec(ctx,
		`insert into access_tokens (session_id, token_hash, expires_at) values ($1, $2, now() + interval '1 hour')`,
		sessionID, HashToken(token),
	); err != nil {
		t.Fatal(err)
	}
	return userID, token
}

func adminUserID(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var userID string
	if err := pool.QueryRow(context.Background(), `select id from users where email = 'admin@test'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	return userID
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

	rec = do(t, h, token, "GET", "/sets", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list sets: %d %s", rec.Code, rec.Body.String())
	}
	var listed []struct {
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		KeyCount int64           `json:"key_count"`
		Keys     json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID || listed[0].Name != "billing" || listed[0].KeyCount != 2 {
		t.Fatalf("unexpected list response: %s", rec.Body.String())
	}
	if listed[0].Keys != nil {
		t.Fatalf("list response should not include keys: %s", rec.Body.String())
	}

	rec = do(t, h, token, "PUT", "/sets/"+created.ID, `{"name":"billing-renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename set: %d %s", rec.Code, rec.Body.String())
	}
	var renamed struct {
		ID   string   `json:"id"`
		Name string   `json:"name"`
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &renamed); err != nil {
		t.Fatal(err)
	}
	if renamed.ID != created.ID || renamed.Name != "billing-renamed" || len(renamed.Keys) != 2 {
		t.Fatalf("unexpected rename response: %s", rec.Body.String())
	}

	// The creator (admin) can read it back, and the audit shows the create.
	if rec := do(t, h, token, "GET", "/sets/"+created.ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("get set: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, token, "GET", "/sets/"+created.ID+"/audit", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get set audit: %d %s", rec.Code, rec.Body.String())
	}
	var audit []struct {
		Action           string `json:"action"`
		Actor            string `json:"actor"`
		ActorEmail       string `json:"actor_email"`
		ActorName        string `json:"actor_name"`
		ActorDisplayName string `json:"actor_display_name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit) == 0 || audit[0].Actor == "" || audit[0].ActorEmail != "admin@test" || audit[0].ActorName != "admin@test" {
		t.Fatalf("expected enriched actor audit rows, got %s", rec.Body.String())
	}
}

func TestMeIncludesGlobalPermissions(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	memberID, member := seedUser(t, s.pool, "global-member@test", "member")

	t.Run("member sees active global grants", func(t *testing.T) {
		grantVia(t, h, admin, memberID, "group.create", "global", "")
		grantVia(t, h, admin, memberID, "host.add", "global", "")
		grantVia(t, h, admin, memberID, "set.add", "global", "")

		rec := do(t, h, member, "GET", "/me", "")
		requireCode(t, rec, http.StatusOK)
		var me struct {
			ID                string   `json:"id"`
			Email             string   `json:"email"`
			GlobalPermissions []string `json:"global_permissions"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
			t.Fatal(err)
		}
		if me.ID != memberID || me.Email != "global-member@test" {
			t.Fatalf("unexpected me response: %s", rec.Body.String())
		}
		got := map[string]bool{}
		for _, permission := range me.GlobalPermissions {
			got[permission] = true
		}
		for _, permission := range []string{"group.create", "host.add", "set.add"} {
			if !got[permission] {
				t.Fatalf("missing global permission %q in %s", permission, rec.Body.String())
			}
		}
		if got["secret.add"] {
			t.Fatalf("unexpected ungranted permission in %s", rec.Body.String())
		}
	})

	t.Run("admin sees effective global permissions", func(t *testing.T) {
		rec := do(t, h, admin, "GET", "/me", "")
		requireCode(t, rec, http.StatusOK)
		var me struct {
			GlobalPermissions []string `json:"global_permissions"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, permission := range me.GlobalPermissions {
			got[permission] = true
		}
		for _, permission := range []string{"group.create", "host.add", "secret.add", "set.add"} {
			if !got[permission] {
				t.Fatalf("missing admin global permission %q in %s", permission, rec.Body.String())
			}
		}
	})
}

func TestResourceResponsesIncludePermissions(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	memberID, member := seedUser(t, s.pool, "resource-perms@test", "member")

	groupID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"perms-group"}`))
	secretID := idOf(t, do(t, h, admin, "POST", "/secrets", `{"label":"perms-secret","password":"hidden"}`))
	setID := idOf(t, do(t, h, admin, "POST", "/sets", `{"name":"perms-set","entries":[{"key":"K","value":"v"}]}`))
	hostID := seedHost(t, s.pool, []string{"deploy"})

	grantVia(t, h, admin, memberID, "group.read", "group", groupID)
	grantVia(t, h, admin, memberID, "group.manage", "group", groupID)
	grantVia(t, h, admin, memberID, "secret.read", "secret", secretID)
	grantVia(t, h, admin, memberID, "set.read", "set", setID)
	grantVia(t, h, admin, memberID, "host.access", "host", hostID)
	grantVia(t, h, admin, memberID, "host.audit", "host", hostID)
	grantVia(t, h, admin, memberID, "host.revoke", "host", hostID)
	grantVia(t, h, admin, memberID, "host.upgrade", "host", hostID)

	assertPermissions := func(token, path string, want []string) {
		t.Helper()
		rec := do(t, h, token, "GET", path, "")
		requireCode(t, rec, http.StatusOK)
		var response struct {
			Permissions []string `json:"permissions"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if !sameStrings(response.Permissions, want) {
			t.Fatalf("%s permissions = %v, want %v: %s", path, response.Permissions, want, rec.Body.String())
		}
	}

	assertPermissions(member, "/groups/"+groupID, []string{"group.read", "group.manage"})
	assertPermissions(member, "/secrets/"+secretID, []string{"secret.read"})
	assertPermissions(member, "/sets/"+setID, []string{"set.read"})
	assertPermissions(member, "/hosts/"+hostID, []string{"host.access", "host.audit", "host.revoke", "host.upgrade"})

	assertPermissions(admin, "/groups/"+groupID, []string{"group.read", "group.manage"})
	assertPermissions(admin, "/secrets/"+secretID, []string{"secret.read", "secret.update", "secret.delete"})
	assertPermissions(admin, "/sets/"+setID, []string{"set.read", "set.manage"})
	assertPermissions(admin, "/hosts/"+hostID, []string{"host.access", "host.audit", "host.revoke", "host.upgrade"})
}

func TestHostOperationPermissions(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()

	auditHostID := seedHost(t, s.pool, []string{"deploy"})
	revokeHostID := seedHost(t, s.pool, []string{"deploy"})
	upgradeHostID := seedHost(t, s.pool, []string{"deploy"})
	memberID, member := seedUser(t, s.pool, "host-ops@test", "member")

	requireCode(t, do(t, h, member, "GET", "/hosts/"+auditHostID+"/access-audit", ""), http.StatusForbidden)
	grantVia(t, h, admin, memberID, "host.audit", "host", auditHostID)
	requireCode(t, do(t, h, member, "GET", "/hosts/"+auditHostID+"/access-audit", ""), http.StatusOK)

	requireCode(t, do(t, h, member, "POST", "/hosts/"+revokeHostID+"/revoke", ""), http.StatusForbidden)
	grantVia(t, h, admin, memberID, "host.revoke", "host", revokeHostID)
	requireCode(t, do(t, h, member, "POST", "/hosts/"+revokeHostID+"/revoke", ""), http.StatusNoContent)
	if host := getHost(t, s, revokeHostID); host.Status != "revoked" {
		t.Fatalf("expected host to be revoked, got %q", host.Status)
	}

	requireCode(t, do(t, h, member, "POST", "/hosts/"+upgradeHostID+"/upgrade", `{"version":"bad"}`), http.StatusForbidden)
	grantVia(t, h, admin, memberID, "host.upgrade", "host", upgradeHostID)
	requireCode(t, do(t, h, member, "POST", "/hosts/"+upgradeHostID+"/upgrade", `{"version":"bad"}`), http.StatusBadRequest)
}

func TestHostAccessAuditIncludesGrantHolders(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	adminID := adminUserID(t, s.pool)
	hostID := seedHost(t, s.pool, []string{"deploy"})

	rec := do(t, h, admin, "GET", "/hosts/"+hostID+"/access-audit", "")
	requireCode(t, rec, http.StatusOK)
	var audit hostAccessAuditView
	if err := json.Unmarshal(rec.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries) != 0 {
		t.Fatalf("admin API bypass must not appear as a host grant: %s", rec.Body.String())
	}

	grantVia(t, h, admin, adminID, "host.access", "host", hostID)
	rec = do(t, h, admin, "GET", "/hosts/"+hostID+"/access-audit", "")
	requireCode(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries) != 1 || len(audit.Entries[0].Paths) != 1 ||
		audit.Entries[0].Paths[0].Via != "direct" || audit.Entries[0].Paths[0].Permission != "host.access" {
		t.Fatalf("host.access grant should be reported even before an SSH key exists: %s", rec.Body.String())
	}
	if len(audit.Entries[0].Fingerprints) != 0 {
		t.Fatalf("grant without an SSH key should report no fingerprints: %s", rec.Body.String())
	}

	fp := seedKey(t, s.pool, adminID)
	rec = do(t, h, admin, "GET", "/hosts/"+hostID+"/access-audit", "")
	requireCode(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries) != 1 || len(audit.Entries[0].Paths) != 1 ||
		audit.Entries[0].Paths[0].Via != "direct" || audit.Entries[0].Paths[0].Permission != "host.access" {
		t.Fatalf("explicit host.access grant should be reported in host audit: %s", rec.Body.String())
	}
	if len(audit.Entries[0].Fingerprints) != 1 || audit.Entries[0].Fingerprints[0] != fp {
		t.Fatalf("expected SSH key fingerprint in audit response: %s", rec.Body.String())
	}
}

func TestHostAccessAuditIncludesGroupGrant(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	adminID := adminUserID(t, s.pool)
	hostID := seedHost(t, s.pool, []string{"deploy"})
	groupID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"admins"}`))

	requireCode(t, do(t, h, admin, "POST", "/groups/"+groupID+"/resources",
		fmt.Sprintf(`{"resource_kind":"host","resource_id":%q}`, hostID)), http.StatusNoContent)
	grantVia(t, h, admin, adminID, "host.access", "group", groupID)

	rec := do(t, h, admin, "GET", "/hosts/"+hostID+"/access-audit", "")
	requireCode(t, rec, http.StatusOK)
	var audit hostAccessAuditView
	if err := json.Unmarshal(rec.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries) != 1 || len(audit.Entries[0].Paths) != 1 ||
		audit.Entries[0].Paths[0].Via != "group" || audit.Entries[0].Paths[0].GroupID != groupID {
		t.Fatalf("group host.access grant should include the group path: %s", rec.Body.String())
	}
	if len(audit.Entries[0].Fingerprints) != 0 {
		t.Fatalf("group grant without an SSH key should report no fingerprints: %s", rec.Body.String())
	}

	fp := seedKey(t, s.pool, adminID)
	rec = do(t, h, admin, "GET", "/hosts/"+hostID+"/access-audit", "")
	requireCode(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries[0].Fingerprints) != 1 || audit.Entries[0].Fingerprints[0] != fp {
		t.Fatalf("expected SSH key fingerprint in group audit response: %s", rec.Body.String())
	}
}

func TestHostAccessAuditPaginatesByUserWithPaths(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	hostID := seedHost(t, s.pool, []string{"deploy"})
	firstID, _ := seedUser(t, s.pool, "aaa-access@test", "member")
	secondID, _ := seedUser(t, s.pool, "bbb-access@test", "member")

	groupA := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"a"}`))
	groupB := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"b"}`))
	for _, groupID := range []string{groupA, groupB} {
		requireCode(t, do(t, h, admin, "POST", "/groups/"+groupID+"/resources",
			fmt.Sprintf(`{"resource_kind":"host","resource_id":%q}`, hostID)), http.StatusNoContent)
		grantVia(t, h, admin, firstID, "host.access", "group", groupID)
	}
	grantVia(t, h, admin, firstID, "host.access", "host", hostID)
	grantVia(t, h, admin, secondID, "host.access", "host", hostID)

	rec := do(t, h, admin, "GET", "/hosts/"+hostID+"/access-audit?limit=1", "")
	requireCode(t, rec, http.StatusOK)
	var first hostAccessAuditView
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Entries) != 1 || first.Entries[0].UserID != firstID || len(first.Entries[0].Paths) != 3 || first.NextCursor == "" {
		t.Fatalf("first page should contain one user with all access paths and a cursor: %s", rec.Body.String())
	}

	rec = do(t, h, admin, "GET", "/hosts/"+hostID+"/access-audit?limit=1&cursor="+url.QueryEscape(first.NextCursor), "")
	requireCode(t, rec, http.StatusOK)
	var second hostAccessAuditView
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Entries) != 1 || second.Entries[0].UserID != secondID || len(second.Entries[0].Paths) != 1 || second.NextCursor != "" {
		t.Fatalf("second page should advance to next user, got %s", rec.Body.String())
	}
}

func TestHostAuditEnrichesKnownFingerprints(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	adminID := adminUserID(t, s.pool)
	knownFP := seedKey(t, s.pool, adminID)
	hostID := seedHost(t, s.pool, []string{"deploy"})

	if _, err := s.pool.Exec(context.Background(),
		`insert into ssh_access_logs (host_id, hostname, account, allowed, at, fingerprint)
		 values ($1, 'h', 'sevena', true, now() - interval '1 minute', $2),
		        ($1, 'h', 'sevena', true, now(), 'SHA256:unknown')`,
		hostID, knownFP,
	); err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, admin, "GET", "/hosts/"+hostID+"/audit", "")
	requireCode(t, rec, http.StatusOK)
	var resp page[hostAuditView]
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	audit := resp.Items
	if len(audit) != 2 {
		t.Fatalf("expected two audit rows, got %s", rec.Body.String())
	}
	if audit[0].Fingerprint != "SHA256:unknown" || audit[0].UserID != "" {
		t.Fatalf("unknown fingerprint should stay anonymous: %s", rec.Body.String())
	}
	if audit[1].Fingerprint != knownFP || audit[1].UserID != adminID || audit[1].UserEmail != "admin@test" {
		t.Fatalf("known fingerprint should include user details: %s", rec.Body.String())
	}
}

func TestHostAuditPaginates(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	hostID := seedHost(t, s.pool, []string{"deploy"})

	for i := 0; i < 5; i++ {
		if _, err := s.pool.Exec(context.Background(),
			`insert into ssh_access_logs (host_id, hostname, account, allowed, at, fingerprint)
			 values ($1, 'h', 'sevena', true, now() - ($2 || ' seconds')::interval, 'SHA256:x')`,
			hostID, i,
		); err != nil {
			t.Fatal(err)
		}
	}

	rec := do(t, h, admin, "GET", "/hosts/"+hostID+"/audit?limit=2", "")
	requireCode(t, rec, http.StatusOK)
	var first page[hostAuditView]
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("expected 2 items with a next cursor, got %s", rec.Body.String())
	}

	rec = do(t, h, admin, "GET", "/hosts/"+hostID+"/audit?limit=2&cursor="+url.QueryEscape(first.NextCursor), "")
	requireCode(t, rec, http.StatusOK)
	var second page[hostAuditView]
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 2 || second.NextCursor == "" {
		t.Fatalf("expected 2 more items with a next cursor, got %s", rec.Body.String())
	}
	if !second.Items[0].At.Before(first.Items[1].At) {
		t.Fatalf("page two should continue after page one")
	}

	rec = do(t, h, admin, "GET", "/hosts/"+hostID+"/audit?limit=2&cursor="+url.QueryEscape(second.NextCursor), "")
	requireCode(t, rec, http.StatusOK)
	var third page[hostAuditView]
	if err := json.Unmarshal(rec.Body.Bytes(), &third); err != nil {
		t.Fatal(err)
	}
	if len(third.Items) != 1 || third.NextCursor != "" {
		t.Fatalf("last page should have 1 item and no cursor, got %s", rec.Body.String())
	}
}

func TestHostAuditFilters(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	adminID := adminUserID(t, s.pool)
	knownFP := seedKey(t, s.pool, adminID)
	hostID := seedHost(t, s.pool, []string{"deploy"})

	if _, err := s.pool.Exec(context.Background(),
		`insert into ssh_access_logs (host_id, hostname, account, allowed, at, fingerprint)
		 values ($1, 'h', 'deploy', true,  now() - interval '2 hours', $2),
		        ($1, 'h', 'root',   false, now() - interval '1 hour',  'SHA256:unknown')`,
		hostID, knownFP,
	); err != nil {
		t.Fatal(err)
	}

	get := func(query string) page[hostAuditView] {
		t.Helper()
		rec := do(t, h, admin, "GET", "/hosts/"+hostID+"/audit"+query, "")
		requireCode(t, rec, http.StatusOK)
		var resp page[hostAuditView]
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if got := get("?success=false"); len(got.Items) != 1 || got.Items[0].Account != "root" {
		t.Fatalf("success=false should return the denied row, got %+v", got.Items)
	}
	if got := get("?user_id=" + adminID); len(got.Items) != 1 || got.Items[0].UserID != adminID {
		t.Fatalf("user_id filter should return the admin's row, got %+v", got.Items)
	}
	if got := get("?q=root"); len(got.Items) != 1 || got.Items[0].Account != "root" {
		t.Fatalf("q=root should match the account, got %+v", got.Items)
	}
	from := time.Now().Add(-90 * time.Minute).UTC().Format(time.RFC3339)
	if got := get("?from=" + url.QueryEscape(from)); len(got.Items) != 1 || got.Items[0].Account != "root" {
		t.Fatalf("from filter should exclude the older row, got %+v", got.Items)
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

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func requireCode(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("got %d, want %d: %s", rec.Code, want, rec.Body.String())
	}
}

func idOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	requireCode(t, rec, http.StatusOK)
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.ID == "" {
		t.Fatalf("no id in response: %s", rec.Body.String())
	}
	return v.ID
}

// grantVia creates a grant through the admin API. Empty targetID means a global grant.
func grantVia(t *testing.T, h http.Handler, adminTok, userID, perm, kind, targetID string) {
	t.Helper()
	body := fmt.Sprintf(`{"user_id":%q,"permission":%q,"target_kind":%q,"target_id":%q}`, userID, perm, kind, targetID)
	requireCode(t, do(t, h, adminTok, "POST", "/grants", body), http.StatusOK)
}

func seedKey(t *testing.T, pool *pgxpool.Pool, userID string) string {
	t.Helper()
	fp := "SHA256:key-" + userID
	if _, err := pool.Exec(context.Background(),
		`insert into public_keys (user_id, label, key_type, key_blob, fingerprint)
		 values ($1, 'test', 'ssh-ed25519', 'BLOB', $2)`, userID, fp); err != nil {
		t.Fatal(err)
	}
	return fp
}

func seedHost(t *testing.T, pool *pgxpool.Pool, accounts []string) string {
	return seedHostKey(t, pool, accounts, "")
}

func seedHostKey(t *testing.T, pool *pgxpool.Pool, accounts []string, encKey string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`insert into hosts (name, hostname, identity_key, accounts, status, encryption_key)
		 values ('h', 'h', 'hostkey-' || gen_random_uuid()::text, $1, 'active', $2) returning id`, accounts, encKey).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func getHost(t *testing.T, s *Server, hostID string) db.Host {
	t.Helper()
	id, err := parseUUID(hostID)
	if err != nil {
		t.Fatal(err)
	}
	host, err := s.q.GetHostByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func snapshotHas(t *testing.T, s *Server, host db.Host, fp string) bool {
	t.Helper()
	snap, err := s.buildSnapshot(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range snap.Entries {
		if e.Fingerprint == fp {
			return true
		}
	}
	return false
}

// TestAuthzMatrix is the core security guarantee: members reach only what they're
// granted, creators own what they make, admins bypass, and group grants cascade.
func TestAuthzMatrix(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	memberID, member := seedUser(t, s.pool, "member@test", "member")

	secretID := idOf(t, do(t, h, admin, "POST", "/secrets", `{"label":"db","password":"p"}`))

	t.Run("no grant is denied", func(t *testing.T) {
		requireCode(t, do(t, h, member, "GET", "/secrets/"+secretID, ""), http.StatusForbidden)
	})

	t.Run("a grant allows read", func(t *testing.T) {
		grantVia(t, h, admin, memberID, "secret.read", "secret", secretID)
		requireCode(t, do(t, h, member, "GET", "/secrets/"+secretID, ""), http.StatusOK)
	})

	var setID string
	t.Run("creator owns what they create", func(t *testing.T) {
		grantVia(t, h, admin, memberID, "set.add", "global", "")
		setID = idOf(t, do(t, h, member, "POST", "/sets", `{"name":"billing","entries":[{"key":"K","value":"v"}]}`))
		// grantOwner gave the creator set.read + set.manage in the same tx.
		requireCode(t, do(t, h, member, "GET", "/sets/"+setID, ""), http.StatusOK)
	})

	t.Run("admin bypasses grants", func(t *testing.T) {
		// admin holds no grant on the member's set but reads it anyway.
		requireCode(t, do(t, h, admin, "GET", "/sets/"+setID, ""), http.StatusOK)
	})

	t.Run("group grant cascades to members", func(t *testing.T) {
		s2 := idOf(t, do(t, h, admin, "POST", "/secrets", `{"label":"db2","password":"p"}`))
		requireCode(t, do(t, h, member, "GET", "/secrets/"+s2, ""), http.StatusForbidden)

		groupID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"g"}`))
		requireCode(t, do(t, h, admin, "POST", "/groups/"+groupID+"/resources",
			fmt.Sprintf(`{"resource_kind":"secret","resource_id":%q}`, s2)), http.StatusNoContent)
		grantVia(t, h, admin, memberID, "secret.read", "group", groupID)

		requireCode(t, do(t, h, member, "GET", "/secrets/"+s2, ""), http.StatusOK)
	})

	t.Run("set group grant cascades to members", func(t *testing.T) {
		groupSetID := idOf(t, do(t, h, admin, "POST", "/sets", `{"name":"ops","entries":[{"key":"TOKEN","value":"v"}]}`))
		requireCode(t, do(t, h, member, "GET", "/sets/"+groupSetID, ""), http.StatusForbidden)

		groupID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"sets"}`))
		requireCode(t, do(t, h, admin, "POST", "/groups/"+groupID+"/resources",
			fmt.Sprintf(`{"resource_kind":"set","resource_id":%q}`, groupSetID)), http.StatusNoContent)
		grantVia(t, h, admin, memberID, "set.read", "group", groupID)

		requireCode(t, do(t, h, member, "GET", "/sets/"+groupSetID, ""), http.StatusOK)
		rec := do(t, h, member, "GET", "/sets", "")
		requireCode(t, rec, http.StatusOK)
		var sets []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &sets); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, set := range sets {
			found = found || set.ID == groupSetID
		}
		if !found {
			t.Fatalf("expected group-readable set in list response: %s", rec.Body.String())
		}
	})

	t.Run("members need host.add to create enrollment tokens", func(t *testing.T) {
		rec := do(t, h, member, "POST", "/enroll-tokens", `{"label":"member-host","accounts":["deploy"],"ttl_hours":1}`)
		requireCode(t, rec, http.StatusForbidden)

		grantVia(t, h, admin, memberID, "host.add", "global", "")
		rec = do(t, h, member, "POST", "/enroll-tokens", `{"label":"member-host","accounts":["deploy"],"ttl_hours":1}`)
		requireCode(t, rec, http.StatusOK)
		var tokenResp struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &tokenResp); err != nil {
			t.Fatal(err)
		}
		if tokenResp.Token == "" {
			t.Fatalf("expected enrollment token response, got %s", rec.Body.String())
		}

		enrollBody := fmt.Sprintf(
			`{"token":%q,"hostname":"actual-hostname","public_key":"hostkey-labeled","encryption_key":"enckey-labeled","machine_id":"machine-labeled"}`,
			tokenResp.Token,
		)
		rec = do(t, h, "", "POST", "/enroll", enrollBody)
		requireCode(t, rec, http.StatusOK)
		var enrollResp struct {
			HostID string `json:"host_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &enrollResp); err != nil {
			t.Fatal(err)
		}
		host := getHost(t, s, enrollResp.HostID)
		if host.Name != "member-host" || host.Hostname != "actual-hostname" {
			t.Fatalf("token label should become host name while hostname stays factual: name=%q hostname=%q", host.Name, host.Hostname)
		}
	})

	t.Run("host list is scoped to host.access", func(t *testing.T) {
		allowedHostID := seedHost(t, s.pool, []string{"deploy"})
		seedHost(t, s.pool, []string{"deploy"})
		grantVia(t, h, admin, memberID, "host.access", "host", allowedHostID)

		rec := do(t, h, member, "GET", "/hosts", "")
		requireCode(t, rec, http.StatusOK)
		var memberHosts []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &memberHosts); err != nil {
			t.Fatal(err)
		}
		if len(memberHosts) != 1 || memberHosts[0].ID != allowedHostID {
			t.Fatalf("expected only granted host, got %s", rec.Body.String())
		}

		rec = do(t, h, admin, "GET", "/hosts", "")
		requireCode(t, rec, http.StatusOK)
		var adminHosts []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &adminHosts); err != nil {
			t.Fatal(err)
		}
		if len(adminHosts) < 2 {
			t.Fatalf("expected admin to see all active hosts, got %s", rec.Body.String())
		}
	})

	t.Run("host list includes group-granted hosts", func(t *testing.T) {
		hostID := seedHost(t, s.pool, []string{"deploy"})
		groupID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"host-group"}`))
		requireCode(t, do(t, h, admin, "POST", "/groups/"+groupID+"/resources",
			fmt.Sprintf(`{"resource_kind":"host","resource_id":%q}`, hostID)), http.StatusNoContent)
		grantVia(t, h, admin, memberID, "host.access", "group", groupID)

		rec := do(t, h, member, "GET", "/hosts", "")
		requireCode(t, rec, http.StatusOK)
		var memberHosts []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &memberHosts); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, host := range memberHosts {
			found = found || host.ID == hostID
		}
		if !found {
			t.Fatalf("expected group-granted host in list, got %s", rec.Body.String())
		}
	})
}

func TestGroupUpdate(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()

	groupID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"ops","description":"old"}`))
	path := "/groups/" + groupID

	t.Run("admin can update group metadata", func(t *testing.T) {
		rec := do(t, h, admin, "PUT", path, `{"name":"platform","description":"new"}`)
		requireCode(t, rec, http.StatusOK)
		var updated struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
			t.Fatal(err)
		}
		if updated.ID != groupID || updated.Name != "platform" || updated.Description != "new" {
			t.Fatalf("unexpected update response: %s", rec.Body.String())
		}
	})

	readerID, reader := seedUser(t, s.pool, "group-reader@test", "member")
	grantVia(t, h, admin, readerID, "group.read", "group", groupID)
	t.Run("group read alone cannot update", func(t *testing.T) {
		requireCode(t, do(t, h, reader, "PUT", path, `{"name":"reader","description":"denied"}`), http.StatusForbidden)
	})

	managerID, manager := seedUser(t, s.pool, "group-manager@test", "member")
	grantVia(t, h, admin, managerID, "group.manage", "group", groupID)
	t.Run("group manager can update", func(t *testing.T) {
		rec := do(t, h, manager, "PUT", path, `{"name":"managed","description":"by member"}`)
		requireCode(t, rec, http.StatusOK)
		var updated struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Name != "managed" || updated.Description != "by member" {
			t.Fatalf("unexpected manager update response: %s", rec.Body.String())
		}
	})

	t.Run("empty name is rejected", func(t *testing.T) {
		requireCode(t, do(t, h, admin, "PUT", path, `{"name":"","description":"x"}`), http.StatusBadRequest)
	})

	t.Run("missing group returns not found", func(t *testing.T) {
		missing := "00000000-0000-0000-0000-000000000000"
		requireCode(t, do(t, h, admin, "PUT", "/groups/"+missing, `{"name":"missing"}`), http.StatusNotFound)
	})
}

func TestGroupDetailEnrichesResources(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()

	hostID := seedHost(t, s.pool, []string{"deploy"})
	secretID := idOf(t, do(t, h, admin, "POST", "/secrets", `{"label":"db","url":"https://db.example","username":"root","password":"hidden"}`))
	setID := idOf(t, do(t, h, admin, "POST", "/sets", `{"name":"ops-env","entries":[{"key":"TOKEN","value":"v"}]}`))
	groupID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"ops"}`))

	for _, resource := range []struct {
		kind string
		id   string
	}{
		{"host", hostID},
		{"secret", secretID},
		{"set", setID},
	} {
		body := fmt.Sprintf(`{"resource_kind":%q,"resource_id":%q}`, resource.kind, resource.id)
		requireCode(t, do(t, h, admin, "POST", "/groups/"+groupID+"/resources", body), http.StatusNoContent)
	}

	rec := do(t, h, admin, "GET", "/groups/"+groupID, "")
	requireCode(t, rec, http.StatusOK)
	var detail struct {
		Resources []struct {
			ResourceKind string          `json:"resource_kind"`
			ResourceID   string          `json:"resource_id"`
			DisplayName  string          `json:"display_name"`
			Host         json.RawMessage `json:"host"`
			Secret       json.RawMessage `json:"secret"`
			Set          json.RawMessage `json:"set"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, resource := range detail.Resources {
		switch resource.ResourceKind {
		case "host":
			var host struct {
				ID       string   `json:"id"`
				Name     string   `json:"name"`
				Hostname string   `json:"hostname"`
				Accounts []string `json:"accounts"`
			}
			if err := json.Unmarshal(resource.Host, &host); err != nil {
				t.Fatal(err)
			}
			if host.ID != hostID || host.Name != "h" || host.Hostname != "h" || len(host.Accounts) != 1 || host.Accounts[0] != "deploy" {
				t.Fatalf("unexpected host enrichment: %s", rec.Body.String())
			}
			seen["host"] = true
		case "secret":
			var secret struct {
				ID       string `json:"id"`
				Label    string `json:"label"`
				URL      string `json:"url"`
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.Unmarshal(resource.Secret, &secret); err != nil {
				t.Fatal(err)
			}
			if secret.ID != secretID || secret.Label != "db" || secret.URL != "https://db.example" || secret.Username != "root" || secret.Password != "" {
				t.Fatalf("unexpected secret enrichment: %s", rec.Body.String())
			}
			seen["secret"] = true
		case "set":
			var set struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				KeyCount int64  `json:"key_count"`
			}
			if err := json.Unmarshal(resource.Set, &set); err != nil {
				t.Fatal(err)
			}
			if set.ID != setID || set.Name != "ops-env" || set.KeyCount != 1 {
				t.Fatalf("unexpected set enrichment: %s", rec.Body.String())
			}
			seen["set"] = true
		}
		if resource.DisplayName == "" {
			t.Fatalf("expected display_name for %s resource: %s", resource.ResourceKind, rec.Body.String())
		}
	}
	for _, kind := range []string{"host", "secret", "set"} {
		if !seen[kind] {
			t.Fatalf("missing %s enrichment: %s", kind, rec.Body.String())
		}
	}
}

func TestListGroupsForResource(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()

	hostID := seedHost(t, s.pool, []string{"deploy"})
	opsID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"ops"}`))
	prodID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"prod"}`))
	hiddenID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"hidden"}`))

	for _, groupID := range []string{opsID, prodID, hiddenID} {
		body := fmt.Sprintf(`{"resource_kind":"host","resource_id":%q}`, hostID)
		requireCode(t, do(t, h, admin, "POST", "/groups/"+groupID+"/resources", body), http.StatusNoContent)
	}

	rec := do(t, h, admin, "GET", "/groups/resources/host/"+hostID, "")
	requireCode(t, rec, http.StatusOK)
	var adminGroups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &adminGroups); err != nil {
		t.Fatal(err)
	}
	if len(adminGroups) != 3 {
		t.Fatalf("expected all host groups, got %s", rec.Body.String())
	}

	memberID, member := seedUser(t, s.pool, "resource-groups@test", "member")
	grantVia(t, h, admin, memberID, "group.read", "group", opsID)
	grantVia(t, h, admin, memberID, "group.read", "group", prodID)

	rec = do(t, h, member, "GET", "/groups/resources/host/"+hostID, "")
	requireCode(t, rec, http.StatusOK)
	var memberGroups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &memberGroups); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, group := range memberGroups {
		got[group.ID] = true
		if group.ID == hiddenID {
			t.Fatalf("member saw unreadable group: %s", rec.Body.String())
		}
	}
	if len(memberGroups) != 2 || !got[opsID] || !got[prodID] {
		t.Fatalf("expected readable host groups only, got %s", rec.Body.String())
	}

	requireCode(t, do(t, h, admin, "GET", "/groups/resources/bad/"+hostID, ""), http.StatusBadRequest)
	requireCode(t, do(t, h, admin, "GET", "/groups/resources/host/not-a-uuid", ""), http.StatusBadRequest)
}

func TestGroupMembers(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()

	groupID := idOf(t, do(t, h, admin, "POST", "/groups", `{"name":"ops"}`))
	memberID, member := seedUser(t, s.pool, "group-member@test", "member")
	grantVia(t, h, admin, memberID, "group.read", "group", groupID)
	grantVia(t, h, admin, memberID, "group.manage", "group", groupID)
	grantVia(t, h, admin, memberID, "host.access", "group", groupID)

	rec := do(t, h, member, "GET", "/groups/"+groupID+"/members", "")
	requireCode(t, rec, http.StatusOK)
	var members []struct {
		UserID      string   `json:"user_id"`
		Email       string   `json:"email"`
		Name        string   `json:"name"`
		Role        string   `json:"role"`
		Status      string   `json:"status"`
		Permissions []string `json:"permissions"`
		Grants      []struct {
			ID         string `json:"id"`
			Permission string `json:"permission"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("expected admin owner plus member, got %s", rec.Body.String())
	}
	var found *struct {
		UserID      string   `json:"user_id"`
		Email       string   `json:"email"`
		Name        string   `json:"name"`
		Role        string   `json:"role"`
		Status      string   `json:"status"`
		Permissions []string `json:"permissions"`
		Grants      []struct {
			ID         string `json:"id"`
			Permission string `json:"permission"`
		} `json:"grants"`
	}
	for i := range members {
		if members[i].UserID == memberID {
			found = &members[i]
			break
		}
	}
	if found == nil || found.Email != "group-member@test" || found.Role != "member" || found.Status != "active" {
		t.Fatalf("expected enriched member row, got %s", rec.Body.String())
	}
	wantPerms := map[string]bool{"group.read": false, "group.manage": false, "host.access": false}
	for _, permission := range found.Permissions {
		if _, ok := wantPerms[permission]; ok {
			wantPerms[permission] = true
		}
	}
	for permission, ok := range wantPerms {
		if !ok {
			t.Fatalf("missing permission %q in %s", permission, rec.Body.String())
		}
	}
	if len(found.Grants) != 3 {
		t.Fatalf("expected one grant per permission for member, got %s", rec.Body.String())
	}

	outsiderID, outsider := seedUser(t, s.pool, "group-outsider@test", "member")
	_ = outsiderID
	requireCode(t, do(t, h, outsider, "GET", "/groups/"+groupID+"/members", ""), http.StatusForbidden)
	requireCode(t, do(t, h, admin, "GET", "/groups/00000000-0000-0000-0000-000000000000/members", ""), http.StatusNotFound)
}

// TestSuspendCutsSSH guards the one invariant that severs a suspended user from
// SSH: HostAccessKeys filters status='active'. SSH bypasses requireAuth, so if
// this regresses, suspended users keep logging in and nothing else catches it.
func TestSuspendCutsSSH(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	memberID, _ := seedUser(t, s.pool, "svc@test", "member")
	fp := seedKey(t, s.pool, memberID)
	hostID := seedHost(t, s.pool, []string{"deploy"})
	grantVia(t, h, admin, memberID, "host.access", "host", hostID)

	host := getHost(t, s, hostID)
	if !snapshotHas(t, s, host, fp) {
		t.Fatal("active user's key should be in the host snapshot")
	}

	requireCode(t, do(t, h, admin, "POST", "/users/"+memberID+"/suspend", ""), http.StatusNoContent)

	if snapshotHas(t, s, host, fp) {
		t.Fatal("suspended user's key must be gone from the snapshot")
	}
}

func TestAddKeyPushesGrantedHostSnapshot(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	hostID := seedHost(t, s.pool, []string{"deploy"})
	grantVia(t, h, admin, adminUserID(t, s.pool), "host.access", "host", hostID)

	send := make(chan protocol.Envelope, 1)
	s.hub.register(hostID, send, func() {})
	defer s.hub.unregister(hostID, send)

	const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIF79/jbso5ZK5Lvu2nbla+Ba7nMgnFIiTRc+G1hohsYO"
	body := fmt.Sprintf(`{"label":"laptop","public_key":"ssh-ed25519 %s user@host"}`, blob)
	requireCode(t, do(t, h, admin, "POST", "/keys", body), http.StatusOK)

	select {
	case env := <-send:
		if env.Type != protocol.TypeSnapshot {
			t.Fatalf("got pushed envelope type %q, want snapshot", env.Type)
		}
		var snap protocol.Snapshot
		if err := json.Unmarshal(env.Data, &snap); err != nil {
			t.Fatal(err)
		}
		if len(snap.Entries) != 1 || snap.Entries[0].Fingerprint != "SHA256:KCcRgYXrek07AU5Sr8Uy/cTjHh/EjelltqNXfmHrVWc" {
			t.Fatalf("pushed snapshot missing new key: %+v", snap.Entries)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for snapshot push after key add")
	}
}

func TestRefreshHostPushesSnapshot(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()
	adminID := adminUserID(t, s.pool)
	fp := seedKey(t, s.pool, adminID)
	hostID := seedHost(t, s.pool, []string{"deploy"})
	grantVia(t, h, admin, adminID, "host.access", "host", hostID)

	send := make(chan protocol.Envelope, 1)
	s.hub.register(hostID, send, func() {})
	defer s.hub.unregister(hostID, send)

	rec := do(t, h, admin, "POST", "/hosts/"+hostID+"/refresh", "")
	requireCode(t, rec, http.StatusOK)
	var refreshed struct {
		Connected bool   `json:"connected"`
		KeyCount  int    `json:"key_count"`
		Seq       uint64 `json:"seq"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &refreshed); err != nil {
		t.Fatal(err)
	}
	if !refreshed.Connected || refreshed.KeyCount != 1 {
		t.Fatalf("unexpected refresh response: %s", rec.Body.String())
	}

	select {
	case env := <-send:
		if env.Type != protocol.TypeSnapshot {
			t.Fatalf("got pushed envelope type %q, want snapshot", env.Type)
		}
		var snap protocol.Snapshot
		if err := json.Unmarshal(env.Data, &snap); err != nil {
			t.Fatal(err)
		}
		if len(snap.Entries) != 1 || snap.Entries[0].Fingerprint != fp {
			t.Fatalf("pushed snapshot missing key %q: %+v", fp, snap.Entries)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forced snapshot push")
	}
}

func TestHostDecommission(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	kp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var hostID string
	if err := s.pool.QueryRow(context.Background(),
		`insert into hosts (name, hostname, identity_key, accounts, status)
		 values ('h', 'h', $1, '{deploy}', 'active') returning id`, kp.PublicKey()).Scan(&hostID); err != nil {
		t.Fatal(err)
	}

	at := time.Now().UTC()
	body, err := json.Marshal(protocol.DecommissionRequest{
		At:        at,
		Signature: kp.Sign(protocol.DecommissionSigningInput(hostID, at)),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireCode(t, do(t, h, "", "POST", "/hosts/"+hostID+"/decommission", string(body)), http.StatusNoContent)

	host := getHost(t, s, hostID)
	if host.Status != "revoked" {
		t.Fatalf("host should be revoked after decommission, got %q", host.Status)
	}
}

// TestBindRequiresBothEnds guards the two-key rule: delivering a set to a host
// needs set.read on the set AND host.access on the host — either alone is denied.
func TestBindRequiresBothEnds(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()

	setID := idOf(t, do(t, h, admin, "POST", "/sets", `{"name":"billing","entries":[{"key":"K","value":"v"}]}`))
	hostID := seedHost(t, s.pool, []string{"deploy"})
	bindPath := "/hosts/" + hostID + "/sets"
	bindBody := fmt.Sprintf(`{"set_id":%q}`, setID)

	aID, aTok := seedUser(t, s.pool, "a@test", "member")
	t.Run("neither end is denied", func(t *testing.T) {
		requireCode(t, do(t, h, aTok, "POST", bindPath, bindBody), http.StatusForbidden)
	})
	t.Run("set.read alone is denied", func(t *testing.T) {
		grantVia(t, h, admin, aID, "set.read", "set", setID)
		requireCode(t, do(t, h, aTok, "POST", bindPath, bindBody), http.StatusForbidden)
	})
	t.Run("both ends succeed", func(t *testing.T) {
		grantVia(t, h, admin, aID, "host.access", "host", hostID)
		requireCode(t, do(t, h, aTok, "POST", bindPath, fmt.Sprintf(`{"set_id":%q,"as_user":"deploy"}`, setID)), http.StatusNoContent)
		rec := do(t, h, aTok, "GET", "/sets/"+setID+"/hosts", "")
		requireCode(t, rec, http.StatusOK)
		var hosts []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
			AsUser   string `json:"as_user"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &hosts); err != nil {
			t.Fatal(err)
		}
		if len(hosts) != 1 || hosts[0].ID != hostID || hosts[0].Name != "h" || hosts[0].Hostname != "h" || hosts[0].AsUser != "deploy" {
			t.Fatalf("unexpected set hosts response: %s", rec.Body.String())
		}
	})

	bID, bTok := seedUser(t, s.pool, "b@test", "member")
	t.Run("host.access alone is denied", func(t *testing.T) {
		grantVia(t, h, admin, bID, "host.access", "host", hostID)
		requireCode(t, do(t, h, bTok, "POST", bindPath, bindBody), http.StatusForbidden)
	})
}

// TestSecretSetDelivery is the end-to-end crypto check: a bound set is sealed to
// the host's X25519 key, opens back to the right values, and leaks no names on the wire.
func TestSecretSetDelivery(t *testing.T) {
	s, admin := newTestServer(t)
	h := s.Handler()

	hostKP, err := hybrid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	hostID := seedHostKey(t, s.pool, []string{"deploy"}, hostKP.PublicKey())

	setID := idOf(t, do(t, h, admin, "POST", "/sets",
		`{"name":"billing","entries":[{"key":"DB_URL","value":"postgres://x"},{"key":"MASTER_KEY","value":"s3cr3t"}]}`))
	requireCode(t, do(t, h, admin, "POST", "/hosts/"+hostID+"/sets", fmt.Sprintf(`{"set_id":%q}`, setID)), http.StatusNoContent)

	host := getHost(t, s, hostID)
	bundle, err := s.buildSecretSets(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	env, err := s.secretSetsEnvelope(context.Background(), host, bundle)
	if err != nil {
		t.Fatal(err)
	}

	// Names/values live inside the seal — none may appear in the wire payload.
	for _, leak := range []string{"billing", "DB_URL", "MASTER_KEY", "s3cr3t"} {
		if strings.Contains(string(env.Data), leak) {
			t.Fatalf("cleartext %q leaked in the sealed payload: %s", leak, env.Data)
		}
	}

	// The host opens the blob with its private key and recovers the values.
	var sealed protocol.SealedSecretSets
	if err := json.Unmarshal(env.Data, &sealed); err != nil {
		t.Fatal(err)
	}
	plain, err := hostKP.Open(sealed.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	var got protocol.SecretSets
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Sets) != 1 || got.Sets[0].Name != "billing" {
		t.Fatalf("unexpected sets: %+v", got.Sets)
	}
	vals := got.Sets[0].Values
	if vals["DB_URL"] != "postgres://x" || vals["MASTER_KEY"] != "s3cr3t" {
		t.Fatalf("values mismatch: %v", vals)
	}
}
