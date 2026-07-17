package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
	"github.com/tofunmiadewuyi/custos/internal/sshkey"
)

// TestClientProtocol exercises a full connection against a stand-in control
// plane: challenge/response auth, snapshot reconcile, ping/pong, and access-log
// forwarding.
func TestClientProtocol(t *testing.T) {
	id, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := id.PublicKey()

	fp, err := sshkey.Fingerprint(testBlob)
	if err != nil {
		t.Fatal(err)
	}
	snapshotEntry := protocol.AccessEntry{
		KeyType: "ssh-ed25519", KeyBlob: testBlob, Fingerprint: fp, Accounts: []string{"deploy"},
	}

	verifyErr := make(chan error, 1)
	gotPong := make(chan struct{}, 1)
	gotLog := make(chan protocol.AccessLog, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/daemon", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		ctx := r.Context()

		// Challenge the daemon and verify its signed reply.
		nonce, _ := identity.NewChallenge()
		challenge, _ := protocol.NewEnvelope(protocol.TypeChallenge, protocol.Challenge{Nonce: nonce})
		if err := wsjson.Write(ctx, conn, challenge); err != nil {
			return
		}
		var env protocol.Envelope
		if err := wsjson.Read(ctx, conn, &env); err != nil {
			return
		}
		var auth protocol.Auth
		json.Unmarshal(env.Data, &auth)
		if env.Type != protocol.TypeAuth || auth.HostID != "host-1" {
			trySend(verifyErr, errUnexpected("bad auth message"))
			return
		}
		trySend(verifyErr, identity.Verify(pub, nonce, auth.Signature))

		// Push the authoritative snapshot, then a ping.
		snapshot, _ := protocol.NewEnvelope(protocol.TypeSnapshot, protocol.Snapshot{Entries: []protocol.AccessEntry{snapshotEntry}})
		wsjson.Write(ctx, conn, snapshot)
		ping, _ := protocol.NewEnvelope(protocol.TypePing, nil)
		wsjson.Write(ctx, conn, ping)

		for {
			var msg protocol.Envelope
			if err := wsjson.Read(ctx, conn, &msg); err != nil {
				return
			}
			switch msg.Type {
			case protocol.TypePong:
				select {
				case gotPong <- struct{}{}:
				default:
				}
			case protocol.TypeAccessLog:
				var lg protocol.AccessLog
				json.Unmarshal(msg.Data, &lg)
				select {
				case gotLog <- lg:
				default:
				}
			}
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store, _ := OpenStore(t.TempDir())
	cache, _ := store.LoadCache()
	client := NewClient(Config{ControlPlane: srv.URL, HostID: "host-1"}, id, cache)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	// Auth signature must verify.
	select {
	case err := <-verifyErr:
		if err != nil {
			t.Fatalf("auth verification failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no auth attempt received")
	}

	// Snapshot must reconcile into the cache.
	waitFor(t, 2*time.Second, func() bool {
		_, ok := cache.Lookup(fp)
		return ok
	}, "snapshot did not reconcile into cache")

	// Ping must be answered with a pong.
	select {
	case <-gotPong:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not answer ping with pong")
	}

	// Access logs must be forwarded upstream.
	client.RecordAccess(protocol.AccessLog{Fingerprint: fp, Account: "deploy", Allowed: true, At: time.Now()})
	select {
	case lg := <-gotLog:
		if lg.Fingerprint != fp || !lg.Allowed {
			t.Fatalf("unexpected access log: %+v", lg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("access log was not forwarded")
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func trySend(ch chan error, err error) {
	select {
	case ch <- err:
	default:
	}
}

type errUnexpected string

func (e errUnexpected) Error() string { return string(e) }
