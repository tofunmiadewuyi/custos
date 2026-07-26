package controlplane

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

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
