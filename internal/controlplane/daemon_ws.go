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

	host, err := s.authenticateDaemon(ctx, conn)
	if err != nil {
		conn.Close(websocket.StatusPolicyViolation, "authentication failed")
		return
	}

	snapshot, err := s.buildSnapshot(ctx, host)
	if err != nil {
		return
	}
	env, err := protocol.NewEnvelope(protocol.TypeSnapshot, snapshot)
	if err != nil {
		return
	}
	if err := wsjson.Write(ctx, conn, env); err != nil {
		return
	}

	go s.pingDaemon(ctx, cancel, conn)
	s.readDaemon(ctx, conn, host)
}

// authenticateDaemon runs the server side of the challenge/response: send a
// nonce, verify the signature against the host's registered identity key.
func (s *Server) authenticateDaemon(ctx context.Context, conn *websocket.Conn) (db.Host, error) {
	ctx, cancel := context.WithTimeout(ctx, daemonReadTimeout)
	defer cancel()

	nonce, err := identity.NewChallenge()
	if err != nil {
		return db.Host{}, err
	}
	challenge, err := protocol.NewEnvelope(protocol.TypeChallenge, protocol.Challenge{Nonce: nonce})
	if err != nil {
		return db.Host{}, err
	}
	if err := wsjson.Write(ctx, conn, challenge); err != nil {
		return db.Host{}, err
	}

	var env protocol.Envelope
	if err := wsjson.Read(ctx, conn, &env); err != nil {
		return db.Host{}, err
	}
	if env.Type != protocol.TypeAuth {
		return db.Host{}, errors.New("expected auth message")
	}
	var auth protocol.Auth
	if err := json.Unmarshal(env.Data, &auth); err != nil {
		return db.Host{}, err
	}

	hostID, err := parseUUID(auth.HostID)
	if err != nil {
		return db.Host{}, err
	}
	host, err := s.q.GetHostByID(ctx, hostID)
	if err != nil {
		return db.Host{}, err
	}
	if err := identity.Verify(host.IdentityKey, nonce, auth.Signature); err != nil {
		return db.Host{}, err
	}
	return host, nil
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

func (s *Server) pingDaemon(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn) {
	ticker := time.NewTicker(daemonPingEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ping, _ := protocol.NewEnvelope(protocol.TypePing, nil)
			if err := wsjson.Write(ctx, conn, ping); err != nil {
				cancel()
				return
			}
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
		PublicKeyID: keyID,
		Account:     lg.Account,
		Allowed:     lg.Allowed,
		At:          pgtype.Timestamptz{Time: lg.At, Valid: true},
	})
	s.q.TouchHostSeen(ctx, host.ID)
}
