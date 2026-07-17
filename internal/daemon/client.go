package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

const (
	readTimeout   = 60 * time.Second // no message (incl. server ping) in this window ⇒ dead link
	maxReadBytes  = 1 << 20          // snapshots can be large; lift the default read cap
	maxReconnect  = 30 * time.Second
	logBufferSize = 256
)

// Client maintains the daemon's live connection to the control plane: it
// authenticates, reconciles the cache from the authoritative snapshot, applies
// the grant/revoke stream, and forwards access logs.
type Client struct {
	cfg      Config
	identity *identity.KeyPair
	cache    *Cache
	logs     chan protocol.AccessLog
}

func NewClient(cfg Config, id *identity.KeyPair, cache *Cache) *Client {
	return &Client{
		cfg:      cfg,
		identity: id,
		cache:    cache,
		logs:     make(chan protocol.AccessLog, logBufferSize),
	}
}

// RecordAccess queues an access-log entry for delivery. It is called from the
// authkeys socket handler and never blocks a login: if the buffer is full
// (control plane down and backed up), the entry is dropped.
func (c *Client) RecordAccess(entry protocol.AccessLog) {
	select {
	case c.logs <- entry:
	default:
		log.Printf("access-log buffer full, dropping entry for %s", entry.Fingerprint)
	}
}

// Run connects and serves until ctx is cancelled, reconnecting with jittered
// backoff whenever the link drops.
func (c *Client) Run(ctx context.Context) error {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := c.connectAndServe(ctx, func() { attempt = 0 })
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempt++
		delay := reconnectDelay(attempt)
		log.Printf("control-plane link down (%v); reconnecting in %s", err, delay.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

// connectAndServe runs one connection to completion. onReady is called once the
// connection is authenticated, so Run can reset its backoff.
func (c *Client) connectAndServe(ctx context.Context, onReady func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, c.wsURL(), nil)
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusInternalError, "shutting down")
	conn.SetReadLimit(maxReadBytes)

	if err := c.authenticate(ctx, conn); err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	onReady()

	send := make(chan protocol.Envelope, logBufferSize)
	go c.writeLoop(ctx, cancel, conn, send)
	go c.forwardLogs(ctx, send)
	return c.readLoop(ctx, conn, send)
}

// authenticate performs the challenge/response: the control plane sends a nonce,
// the daemon signs it with its identity key and names itself.
func (c *Client) authenticate(ctx context.Context, conn *websocket.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	var env protocol.Envelope
	if err := wsjson.Read(ctx, conn, &env); err != nil {
		return err
	}
	if env.Type != protocol.TypeChallenge {
		return fmt.Errorf("expected challenge, got %q", env.Type)
	}
	var ch protocol.Challenge
	if err := json.Unmarshal(env.Data, &ch); err != nil {
		return err
	}
	reply, err := protocol.NewEnvelope(protocol.TypeAuth, protocol.Auth{
		HostID:    c.cfg.HostID,
		Signature: c.identity.Sign(ch.Nonce),
	})
	if err != nil {
		return err
	}
	return wsjson.Write(ctx, conn, reply)
}

// readLoop applies incoming messages until the link fails. A read that exceeds
// readTimeout (no traffic, not even a server ping) is treated as a dead link.
func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn, send chan protocol.Envelope) error {
	for {
		readCtx, cancel := context.WithTimeout(ctx, readTimeout)
		var env protocol.Envelope
		err := wsjson.Read(readCtx, conn, &env)
		cancel()
		if err != nil {
			return err
		}
		if err := c.dispatch(env, send); err != nil {
			return err
		}
	}
}

func (c *Client) dispatch(env protocol.Envelope, send chan protocol.Envelope) error {
	switch env.Type {
	case protocol.TypeSnapshot:
		var s protocol.Snapshot
		if err := json.Unmarshal(env.Data, &s); err != nil {
			return err
		}
		return c.cache.ApplySnapshot(s)
	case protocol.TypeGrant:
		var g protocol.Grant
		if err := json.Unmarshal(env.Data, &g); err != nil {
			return err
		}
		return c.cache.ApplyGrant(g)
	case protocol.TypeRevoke:
		var r protocol.Revoke
		if err := json.Unmarshal(env.Data, &r); err != nil {
			return err
		}
		return c.cache.ApplyRevoke(r)
	case protocol.TypePing:
		pong, _ := protocol.NewEnvelope(protocol.TypePong, nil)
		send <- pong
		return nil
	default:
		return nil // ignore unknown message types for forward compatibility
	}
}

// writeLoop is the sole writer to the connection; both the read loop (pongs) and
// the log forwarder funnel through send. A write failure tears down the link.
func (c *Client) writeLoop(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, send chan protocol.Envelope) {
	for {
		select {
		case <-ctx.Done():
			return
		case env := <-send:
			if err := wsjson.Write(ctx, conn, env); err != nil {
				cancel()
				return
			}
		}
	}
}

func (c *Client) forwardLogs(ctx context.Context, send chan protocol.Envelope) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-c.logs:
			env, err := protocol.NewEnvelope(protocol.TypeAccessLog, entry)
			if err != nil {
				continue
			}
			select {
			case send <- env:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (c *Client) wsURL() string {
	u := c.cfg.ControlPlane
	u = strings.Replace(u, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	return strings.TrimRight(u, "/") + "/daemon"
}

// reconnectDelay grows exponentially to a cap, with jitter to avoid a
// thundering herd when the control plane restarts and every daemon reconnects.
func reconnectDelay(attempt int) time.Duration {
	d := time.Second << min(attempt, 5) // 2s, 4s, ... capped below
	if d > maxReconnect {
		d = maxReconnect
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}
