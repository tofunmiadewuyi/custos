package controlplane

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/tofunmiadewuyi/custos/internal/hybrid"
)

// readRequest reads the body, hybrid-decrypting it when encryption is enabled,
// and unmarshals into v.
func (s *Server) readRequest(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if s.cfg.EncryptionEnabled {
		body, err = hybrid.Open(s.cfg.HybridPrivateKey, body)
		if err != nil {
			return err
		}
	}
	return json.Unmarshal(body, v)
}

// writeResponse marshals v, sealing it to clientPublic when encryption is enabled.
func (s *Server) writeResponse(w http.ResponseWriter, clientPublic []byte, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !s.cfg.EncryptionEnabled {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}
	sealed, err := hybrid.Seal(clientPublic, data)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(sealed)
}
