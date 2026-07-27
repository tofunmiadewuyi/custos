package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

const (
	daemonReadTimeout = 90 * time.Second
	daemonPingEvery   = 30 * time.Second
)

func (s *Server) handleDaemon(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusInternalError, "closing")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	host, version, err := s.authenticateDaemon(ctx, conn)
	if err != nil {
		conn.Close(websocket.StatusPolicyViolation, "authentication failed")
		return
	}
	hostID := uuidString(host.ID)

	if version != "" && version != host.AgentVersion {
		s.q.SetHostVersion(ctx, db.SetHostVersionParams{ID: host.ID, AgentVersion: version})
		host.AgentVersion = version
	}

	send := make(chan protocol.Envelope, 32)
	s.hub.register(hostID, send, cancel)
	defer s.hub.unregister(hostID, send)

	// initial snapshot for the writer to send first
	if snapshot, err := s.buildSnapshot(ctx, host); err == nil {
		if env, err := s.snapshotEnvelope(ctx, host.ID, snapshot); err == nil {
			send <- env
		}
	}

	// sealed secret sets bound to this host, reconciled on every connect
	if sets, err := s.buildSecretSets(ctx, host); err == nil {
		if env, err := s.secretSetsEnvelope(ctx, host.ID, sets); err == nil {
			send <- env
		}
	}

	// A host still behind its desired version gets the upgrade re-pushed on connect.
	if host.DesiredVersion != "" && host.DesiredVersion != host.AgentVersion {
		if up, err := s.buildUpgrade(ctx, host.DesiredVersion); err == nil {
			if env, err := protocol.NewEnvelope(protocol.TypeUpgrade, up); err == nil {
				send <- env
			}
		}
	}

	go s.writeDaemon(ctx, cancel, conn, send)
	s.readDaemon(ctx, conn, host)
}

// authenticateDaemon runs the server side of the challenge/response: send a
// nonce, verify the signature against the host's registered identity key.
func (s *Server) authenticateDaemon(ctx context.Context, conn *websocket.Conn) (db.Host, string, error) {
	ctx, cancel := context.WithTimeout(ctx, daemonReadTimeout)
	defer cancel()

	nonce, err := identity.NewChallenge()
	if err != nil {
		return db.Host{}, "", err
	}
	challenge, err := protocol.NewEnvelope(protocol.TypeChallenge, protocol.Challenge{Nonce: nonce})
	if err != nil {
		return db.Host{}, "", err
	}
	if err := wsjson.Write(ctx, conn, challenge); err != nil {
		return db.Host{}, "", err
	}

	var env protocol.Envelope
	if err := wsjson.Read(ctx, conn, &env); err != nil {
		return db.Host{}, "", err
	}
	if env.Type != protocol.TypeAuth {
		return db.Host{}, "", errors.New("expected auth message")
	}
	var auth protocol.Auth
	if err := json.Unmarshal(env.Data, &auth); err != nil {
		return db.Host{}, "", err
	}

	hostID, err := parseUUID(auth.HostID)
	if err != nil {
		return db.Host{}, "", err
	}
	host, err := s.q.GetHostByID(ctx, hostID)
	if err != nil {
		return db.Host{}, "", err
	}
	if host.Status != "active" {
		return db.Host{}, "", errors.New("host not active")
	}
	if err := identity.Verify(host.IdentityKey, nonce, auth.Signature); err != nil {
		return db.Host{}, "", err
	}
	return host, auth.Version, nil
}

func (s *Server) buildSnapshot(ctx context.Context, host db.Host) (protocol.Snapshot, error) {
	rows, err := s.q.HostAccessKeys(ctx, host.ID)
	if err != nil {
		return protocol.Snapshot{}, err
	}
	entries := make([]protocol.AccessEntry, 0, len(rows))
	for _, k := range rows {
		entries = append(entries, protocol.AccessEntry{
			UserID:      uuidString(k.UserID),
			KeyType:     k.KeyType,
			KeyBlob:     k.KeyBlob,
			Fingerprint: k.Fingerprint,
			Accounts:    host.Accounts,
		})
	}
	return protocol.Snapshot{Entries: entries}, nil
}

// snapshotEnvelope marshals snap, stamps the next per-host seq, and signs it. An
// unset signer (tests) yields an unsigned envelope.
func (s *Server) snapshotEnvelope(ctx context.Context, hostID pgtype.UUID, snap protocol.Snapshot) (protocol.Envelope, error) {
	data, err := json.Marshal(snap)
	if err != nil {
		return protocol.Envelope{}, err
	}
	env := protocol.Envelope{Type: protocol.TypeSnapshot, Data: data}
	if s.signer == nil {
		return env, nil
	}
	seq, err := s.q.NextHostSeq(ctx, hostID)
	if err != nil {
		return protocol.Envelope{}, err
	}
	env.Seq = uint64(seq)
	env.Sig = s.signer.Sign(protocol.SnapshotSigningInput(uuidString(hostID), env.Seq, data))
	return env, nil
}

// writeDaemon is the sole writer to the connection: it pings on a ticker and
// forwards messages pushed onto the send chanel
func (s *Server) writeDaemon(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, send chan protocol.Envelope) {
	ticker := time.NewTicker(daemonPingEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushDaemon(conn, send) // write any queued envelopes (e.g. a revoke purge) before closing
			return
		case <-ticker.C:
			ping, _ := protocol.NewEnvelope(protocol.TypePing, nil)
			if err := wsjson.Write(ctx, conn, ping); err != nil {
				cancel()
				return
			}
		case env := <-send:
			if err := wsjson.Write(ctx, conn, env); err != nil {
				cancel()
				return
			}
		}
	}
}

// flushDaemon drains and writes any envelopes still queued when the connection
// is torn down, on a fresh deadline since the connection ctx is already done.
func flushDaemon(conn *websocket.Conn, send chan protocol.Envelope) {
	for {
		select {
		case env := <-send:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := wsjson.Write(ctx, conn, env)
			cancel()
			if err != nil {
				return
			}
		default:
			return
		}
	}
}

func (s *Server) readDaemon(ctx context.Context, conn *websocket.Conn, host db.Host) {
	for {
		readCtx, cancel := context.WithTimeout(ctx, daemonReadTimeout)
		var env protocol.Envelope
		err := wsjson.Read(readCtx, conn, &env)
		cancel()
		if err != nil {
			return
		}
		if env.Type == protocol.TypeAccessLog {
			var lg protocol.AccessLog
			if err := json.Unmarshal(env.Data, &lg); err == nil {
				s.recordAccessLog(ctx, host, lg)
			}
		}
	}
}

func (s *Server) recordAccessLog(ctx context.Context, host db.Host, lg protocol.AccessLog) {
	var keyID pgtype.UUID
	if pk, err := s.q.GetPublicKeyByFingerprint(ctx, lg.Fingerprint); err == nil {
		keyID = pk.ID
	}
	s.q.InsertSSHAccessLog(ctx, db.InsertSSHAccessLogParams{
		HostID:      host.ID,
		Hostname:    host.Hostname,
		PublicKeyID: keyID,
		Account:     lg.Account,
		Allowed:     lg.Allowed,
		At:          pgtype.Timestamptz{Time: lg.At, Valid: true},
		Fingerprint: lg.Fingerprint,
	})
	s.q.TouchHostSeen(ctx, host.ID)
}
