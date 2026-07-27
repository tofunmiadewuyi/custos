package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// ErrRestart is returned by Run when an upgrade has been staged and the process
// should exit so systemd restarts it into the new binary.
var ErrRestart = errors.New("restart to apply staged upgrade")

const (
	readTimeout   = 60 * time.Second // no message (incl. server ping) in this window ⇒ dead link
	maxReadBytes  = 1 << 20          // snapshots can be large; lift the default read cap
	maxReconnect  = 30 * time.Second
	logBufferSize = 256

	maxBackoffAttempt = 5 // reconnectDelay caps here; used to throttle a rejected host
)

// Client maintains the daemon's live connection to the control plane: it
// authenticates, reconciles the cache from the authoritative snapshot, applies
// the grant/revoke stream, and forwards access logs.
type Client struct {
	cfg       Config
	identity  *identity.KeyPair
	cache     *Cache
	secrets   *SecretStore
	logs      chan protocol.AccessLog
	version   string
	updateDir string

	restart     chan struct{} // closed once an upgrade is staged and ready
	restartOnce sync.Once
	upgrading   atomic.Bool
}

func NewClient(cfg Config, id *identity.KeyPair, cache *Cache, secrets *SecretStore, version, updateDir string) *Client {
	return &Client{
		cfg:       cfg,
		identity:  id,
		cache:     cache,
		secrets:   secrets,
		logs:      make(chan protocol.AccessLog, logBufferSize),
		version:   version,
		updateDir: updateDir,
		restart:   make(chan struct{}),
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
		select {
		case <-c.restart:
			return ErrRestart
		default:
		}
		err := c.connectAndServe(ctx, func() { attempt = 0 })
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-c.restart:
			return ErrRestart
		default:
		}
		// A policy-violation close = control plane rejected us (revoked/unknown), not a transient drop.
		if websocket.CloseStatus(err) == websocket.StatusPolicyViolation {
			if perr := c.cache.Purge(); perr != nil {
				log.Printf("cache purge after rejection failed: %v", perr)
			} else {
				log.Printf("control plane rejected this host; purged local access cache")
			}
			attempt = maxBackoffAttempt
		}
		attempt++
		delay := reconnectDelay(attempt)
		log.Printf("control-plane link down (%v); reconnecting in %s", err, delay.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.restart:
			return ErrRestart
		case <-time.After(delay):
		}
	}
}

// connectAndServe runs one connection to completion. onReady is called once the
// connection is authenticated, so Run can reset its backoff.
func (c *Client) connectAndServe(ctx context.Context, onReady func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A staged upgrade tears down the live connection so Run can exit and restart.
	go func() {
		select {
		case <-c.restart:
			cancel()
		case <-ctx.Done():
		}
	}()

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
		Version:   c.version,
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
		if err := c.verifySnapshot(env); err != nil {
			log.Printf("dropping snapshot: %v", err)
			return nil
		}
		if env.Seq != 0 && env.Seq <= c.cache.Seq() {
			return nil
		}
		var s protocol.Snapshot
		if err := json.Unmarshal(env.Data, &s); err != nil {
			return err
		}
		return c.cache.ApplySnapshot(s, env.Seq)
	case protocol.TypeSecretSets:
		if c.secrets == nil {
			return nil
		}
		if err := c.verifySecretSets(env); err != nil {
			log.Printf("dropping secret sets: %v", err)
			return nil
		}
		if env.Seq != 0 && env.Seq <= c.secrets.Seq() {
			return nil
		}
		var sealed protocol.SealedSecretSets
		if err := json.Unmarshal(env.Data, &sealed); err != nil {
			return err
		}
		if err := c.secrets.Apply(sealed, env.Seq); err != nil {
			log.Printf("dropping secret sets: %v", err)
		}
		return nil
	case protocol.TypeUpgrade:
		var up protocol.Upgrade
		if err := json.Unmarshal(env.Data, &up); err != nil {
			return err
		}
		c.handleUpgrade(up)
		return nil
	case protocol.TypePing:
		pong, _ := protocol.NewEnvelope(protocol.TypePong, nil)
		send <- pong
		return nil
	default:
		return nil // ignore unknown message types
	}
}

// handleUpgrade stages the target build in the background (a multi-MB download
// must not block the read loop) and signals a restart once it lands. A no-op if
// already on the target or an upgrade is already running.
func (c *Client) handleUpgrade(up protocol.Upgrade) {
	if up.Version == "" || up.Version == c.version {
		return
	}
	if !c.upgrading.CompareAndSwap(false, true) {
		return
	}
	go func() {
		if err := c.stageUpgrade(context.Background(), up); err != nil {
			log.Printf("upgrade to %s failed: %v", up.Version, err)
			c.upgrading.Store(false)
			return
		}
		log.Printf("upgrade to %s staged; restarting", up.Version)
		c.restartOnce.Do(func() { close(c.restart) })
	}()
}

// verifySnapshot checks the control plane's signature over the snapshot. With no
// stored signing key (dev), it accepts unsigned; once keyed it never downgrades.
func (c *Client) verifySnapshot(env protocol.Envelope) error {
	if c.cfg.SigningPublicKey == "" {
		return nil
	}
	input := protocol.SnapshotSigningInput(c.cfg.HostID, env.Seq, env.Data)
	return identity.Verify(c.cfg.SigningPublicKey, input, env.Sig)
}

// verifySecretSets checks the control plane's signature over a secret-sets push,
// under the sets domain tag. Unsigned is accepted only when no signing key is set.
func (c *Client) verifySecretSets(env protocol.Envelope) error {
	if c.cfg.SigningPublicKey == "" {
		return nil
	}
	input := protocol.SecretSetsSigningInput(c.cfg.HostID, env.Seq, env.Data)
	return identity.Verify(c.cfg.SigningPublicKey, input, env.Sig)
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
