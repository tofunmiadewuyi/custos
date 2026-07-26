package controlplane

import (
	"context"
	"sync"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// daemonConn is one live daemon connection: the outbound channel plus a cancel
// that tears the connection down (used to force-disconnect a revoked host).
type daemonConn struct {
	send   chan protocol.Envelope
	cancel context.CancelFunc
}

// hub tracks live daemon connections by host id so the control plane can push
// updates to them or disconnect them.
type hub struct {
	mu    sync.RWMutex
	conns map[string]*daemonConn
}

func newHub() *hub {
	return &hub{conns: make(map[string]*daemonConn)}
}

func (h *hub) register(hostID string, send chan protocol.Envelope, cancel context.CancelFunc) {
	h.mu.Lock()
	h.conns[hostID] = &daemonConn{send: send, cancel: cancel}
	h.mu.Unlock()
}

// unregister removes a connection, but only if it's still the current one — so a
// dying connection's cleanup can't evict a newer reconnect for the same host.
func (h *hub) unregister(hostID string, send chan protocol.Envelope) {
	h.mu.Lock()
	if c := h.conns[hostID]; c != nil && c.send == send {
		delete(h.conns, hostID)
	}
	h.mu.Unlock()
}

// push delivers envelope to a host's live connection if it has one. It never blocks:
// a full buffer is dropped, since the daemon reconciles from the snapshot on its
// next (re)connect anyway.
func (h *hub) push(hostID string, env protocol.Envelope) {
	h.mu.RLock()
	c := h.conns[hostID]
	h.mu.RUnlock()
	if c == nil {
		return
	}
	select {
	case c.send <- env:
	default:
	}
}

// disconnect queues a final envelope (e.g. a revoke's empty snapshot), then tears the connection down.
func (h *hub) disconnect(hostID string, final protocol.Envelope) {
	h.mu.RLock()
	c := h.conns[hostID]
	h.mu.RUnlock()
	if c == nil {
		return
	}
	select {
	case c.send <- final:
	default:
	}
	c.cancel()
}
