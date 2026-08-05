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

	t.Run("members can create enrollment tokens", func(t *testing.T) {
		rec := do(t, h, member, "POST", "/enroll-tokens", `{"label":"member-host","accounts":["deploy"],"ttl_hours":1}`)
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
