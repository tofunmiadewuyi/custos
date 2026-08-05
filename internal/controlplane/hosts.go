package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// hostDetailView is a single host plus live/derived state.
type hostDetailView struct {
	hostView
	Connected  bool     `json:"connected"`  // WS link up right now
	Encryption bool     `json:"encryption"` // has an X25519 key registered
	Sets       []string `json:"sets"`       // bound secret sets
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	hostID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	if !s.canHost(r.Context(), auth, "host.access", hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	host, err := s.q.GetHostByID(r.Context(), hostID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not load host", err)
		return
	}
	sets := []string{}
	if rows, err := s.q.SetsForHost(r.Context(), hostID); err == nil {
		for _, row := range rows {
			sets = append(sets, row.Name)
		}
	}
	s.writeResponse(w, auth.ClientPublicKey, hostDetailView{
		hostView: hostView{
			ID: uuidString(host.ID), Name: host.Name, Hostname: host.Hostname,
			Accounts: host.Accounts, Status: host.Status,
			AgentVersion: host.AgentVersion, DesiredVersion: host.DesiredVersion,
			EnrolledAt: host.EnrolledAt.Time, LastSeenAt: nullTime(host.LastSeenAt),
		},
		Connected:  s.hub.online(uuidString(host.ID)),
		Encryption: host.EncryptionKey != "",
		Sets:       sets,
	})
}

type hostAuditView struct {
	Account     string    `json:"account"`
	Allowed     bool      `json:"allowed"`
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
}

func (s *Server) handleHostAudit(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	hostID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	if !s.canHost(r.Context(), auth, "host.access", hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rows, err := s.q.ListHostAccessLogs(r.Context(), hostID)
	if err != nil {
		serverError(w, "could not load host audit", err)
		return
	}
	views := make([]hostAuditView, 0, len(rows))
	for _, row := range rows {
		views = append(views, hostAuditView{
			Account: row.Account, Allowed: row.Allowed, Fingerprint: row.Fingerprint, At: row.At.Time,
		})
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

// handleRevokeHost marks a host revoked, then purges and severs it.
// 1. status is set first so the daemon can't reconnect,
// 2. then an empty snapshot is pushed so a live daemon wipes every custos-added key from its cache AND its last-known-good file
// 3. then socket is closed
// machine_id is freed, so the same box may enroll again as a fresh host.
// Idempotent; the row is kept for audit.
func (s *Server) handleRevokeHost(w http.ResponseWriter, r *http.Request) {
	hostID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	if err := s.revokeHost(r.Context(), hostID); errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	} else if err != nil {
		serverError(w, "could not revoke host", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDecommissionHost(w http.ResponseWriter, r *http.Request) {
	hostID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	host, err := s.q.GetHostByID(r.Context(), hostID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "could not decommission host", err)
		return
	}
	if host.Status != "active" {
		http.Error(w, "host not active", http.StatusConflict)
		return
	}
	var req protocol.DecommissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.At.IsZero() || time.Since(req.At) > 5*time.Minute || time.Until(req.At) > 5*time.Minute {
		http.Error(w, "stale decommission request", http.StatusUnauthorized)
		return
	}
	if err := identity.Verify(host.IdentityKey, protocol.DecommissionSigningInput(uuidString(hostID), req.At), req.Signature); err != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	if err := s.revokeHost(r.Context(), hostID); err != nil {
		serverError(w, "could not decommission host", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) revokeHost(ctx context.Context, hostID pgtype.UUID) error {
	n, err := s.q.SetHostStatus(ctx, db.SetHostStatusParams{ID: hostID, Status: "revoked"})
	if err != nil {
		return err
	}
	if n == 0 {
		return pgx.ErrNoRows
	}
	// Empty snapshot: the daemon replaces its whole authorized set with nothing.
	purge, err := s.snapshotEnvelope(ctx, hostID, protocol.Snapshot{Entries: []protocol.AccessEntry{}})
	if err != nil {
		return err
	}
	s.hub.disconnect(uuidString(hostID), purge)
	return nil
}
