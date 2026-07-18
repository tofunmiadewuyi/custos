package controlplane

import (
	"sync"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// hub tracks live daemon connections by host id so the control plane can push
// updates to them. Each connection registers its outbound channel here.
type hub struct {
	mu    sync.RWMutex
	conns map[string]chan protocol.Envelope
}

func newHub() *hub {
	return &hub{conns: make(map[string]chan protocol.Envelope)}
}

func (h *hub) register(hostID string, send chan protocol.Envelope) {
	h.mu.Lock()
	h.conns[hostID] = send
	h.mu.Unlock()
}

// unregister removes a connection, but only if it's still the current one — so a
// dying connection's cleanup can't evict a newer reconnect for the same host.
func (h *hub) unregister(hostID string, send chan protocol.Envelope) {
	h.mu.Lock()
	if h.conns[hostID] == send {
		delete(h.conns, hostID)
	}
	h.mu.Unlock()
}

// push delivers envelope to a host's live connection if it has one. It never blocks:
// a full buffer is dropped, since the daemon reconciles from the snapshot on its
// next (re)connect anyway.
func (h *hub) push(hostID string, env protocol.Envelope) {
	h.mu.RLock()
	send := h.conns[hostID]
	h.mu.RUnlock()
	if send == nil {
		return
	}
	select {
	case send <- env:
	default:
	}
}
