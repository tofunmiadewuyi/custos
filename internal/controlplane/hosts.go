package controlplane

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
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
	n, err := s.q.SetHostStatus(r.Context(), db.SetHostStatusParams{ID: hostID, Status: "revoked"})
	if err != nil {
		serverError(w, "could not revoke host", err)
		return
	}
	if n == 0 {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	// Empty snapshot: the daemon replaces its whole authorized set with nothing.
	purge, err := s.snapshotEnvelope(r.Context(), hostID, protocol.Snapshot{Entries: []protocol.AccessEntry{}})
	if err != nil {
		serverError(w, "could not revoke host", err)
		return
	}
	s.hub.disconnect(uuidString(hostID), purge)
	w.WriteHeader(http.StatusNoContent)
}
