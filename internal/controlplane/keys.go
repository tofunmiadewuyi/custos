package controlplane

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/sshkey"
)

type addKeyRequest struct {
	Label     string `json:"label"`
	PublicKey string `json:"public_key"` // an authorized_keys line
}

type publicKeyView struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Server) handleAddKey(w http.ResponseWriter, r *http.Request) {
	var req addKeyRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	keyType, blob, err := sshkey.ParseAuthorizedKey(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}
	fingerprint, err := sshkey.Fingerprint(blob)
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	auth := authFrom(r.Context())
	key, err := s.q.CreatePublicKey(r.Context(), db.CreatePublicKeyParams{
		UserID:      auth.UserID,
		Label:       req.Label,
		KeyType:     keyType,
		KeyBlob:     blob,
		Fingerprint: fingerprint,
	})
	if err != nil {
		if isUniqueViolation(err) {
			http.Error(w, "key already registered", http.StatusConflict)
			return
		}
		serverError(w, "could not add key", err)
		return
	}
	hosts, _ := s.q.UserGrantedHostIDs(r.Context(), auth.UserID)
	s.pushToHosts(r.Context(), hosts)
	s.writeResponse(w, auth.ClientPublicKey, publicKeyView{
		ID:          uuidString(key.ID),
		Label:       key.Label,
		Fingerprint: key.Fingerprint,
		CreatedAt:   key.CreatedAt.Time,
	})
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	rows, err := s.q.ListUserPublicKeys(r.Context(), auth.UserID)
	if err != nil {
		serverError(w, "could not list keys", err)
		return
	}
	views := make([]publicKeyView, 0, len(rows))
	for _, k := range rows {
		views = append(views, publicKeyView{uuidString(k.ID), k.Label, k.Fingerprint, k.CreatedAt.Time})
	}
	s.writeResponse(w, auth.ClientPublicKey, views)
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	keyID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid key id", http.StatusBadRequest)
		return
	}
	n, err := s.q.DeletePublicKey(r.Context(), db.DeletePublicKeyParams{ID: keyID, UserID: auth.UserID})
	if err != nil {
		serverError(w, "could not delete key", err)
		return
	}
	if n == 0 {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}
	// The key is gone from any host it granted; re-push those snapshots.
	hosts, _ := s.q.UserGrantedHostIDs(r.Context(), auth.UserID)
	s.pushToHosts(r.Context(), hosts)
	w.WriteHeader(http.StatusNoContent)
}
