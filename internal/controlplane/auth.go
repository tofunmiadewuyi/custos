package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/password"
)

const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 30 * 24 * time.Hour

	maxLoginFailures = 5
	loginWindow      = 15 * time.Minute // failures must accumulate within this to lock
	lockDuration     = 15 * time.Minute
)

var (
	errBadCredentials = errors.New("invalid credentials")
	errTooManyAttempts = errors.New("too many failed login attempts")
)

// dummyHash is verified against for unknown emails so login costs the same
// whether or not the account exists, defeating timing-based enumeration.
var dummyHash, _ = password.Hash("timing-equalization-placeholder")

type loginRequest struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	ClientPublicKey []byte `json:"client_public_key"` // X25519, for sealing responses
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return
	}
	if s.cfg.EncryptionEnabled && len(req.ClientPublicKey) == 0 {
		http.Error(w, "client_public_key is required", http.StatusBadRequest)
		return
	}

	pair, err := s.login(r.Context(), req)
	switch {
	case errors.Is(err, errTooManyAttempts):
		http.Error(w, "too many failed attempts; try again later", http.StatusTooManyRequests)
	case errors.Is(err, errBadCredentials):
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	case err != nil:
		serverError(w, "login failed", err)
	default:
		s.writeResponse(w, req.ClientPublicKey, pair)
	}
}

func (s *Server) login(ctx context.Context, req loginRequest) (tokenPair, error) {
	id, err := s.q.GetIdentity(ctx, db.GetIdentityParams{Provider: "password", ExternalID: req.Email})
	if errors.Is(err, pgx.ErrNoRows) {
		password.Verify(dummyHash, req.Password) // equalize timing vs a real verify
		return tokenPair{}, errBadCredentials
	}
	if err != nil {
		return tokenPair{}, err
	}
	if id.LockedUntil.Valid && id.LockedUntil.Time.After(time.Now()) {
		return tokenPair{}, errTooManyAttempts
	}
	if !id.PasswordHash.Valid {
		password.Verify(dummyHash, req.Password)
		return tokenPair{}, errBadCredentials
	}
	ok, err := password.Verify(id.PasswordHash.String, req.Password)
	if err != nil || !ok {
		s.recordFailedLogin(ctx, id)
		return tokenPair{}, errBadCredentials
	}
	s.q.ResetLoginFailures(ctx, id.ID)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return tokenPair{}, err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)

	rawRefresh, refreshHash, err := GenerateToken()
	if err != nil {
		return tokenPair{}, err
	}
	sess, err := q.CreateSession(ctx, db.CreateSessionParams{
		UserID:          id.UserID,
		TokenHash:       refreshHash,
		ClientPublicKey: req.ClientPublicKey,
		ExpiresAt:       expiry(refreshTTL),
	})
	if err != nil {
		return tokenPair{}, err
	}

	rawAccess, err := s.mintAccessToken(ctx, q, sess.ID)
	if err != nil {
		return tokenPair{}, err
	}
	q.TouchIdentityLogin(ctx, id.ID)

	if err := tx.Commit(ctx); err != nil {
		return tokenPair{}, err
	}
	return tokenPair{AccessToken: rawAccess, RefreshToken: rawRefresh}, nil
}

// recordFailedLogin bumps the identity's failure count within the window and
// locks the account once it crosses the threshold. Auto-clears when the lock
// window passes, or on the next successful login.
func (s *Server) recordFailedLogin(ctx context.Context, id db.Identity) {
	count := id.FailedLogins + 1
	if id.LastFailedAt.Valid && time.Since(id.LastFailedAt.Time) > loginWindow {
		count = 1 // window elapsed, start a fresh streak
	}
	var lockedUntil pgtype.Timestamptz
	if count >= maxLoginFailures {
		lockedUntil = pgtype.Timestamptz{Time: time.Now().Add(lockDuration), Valid: true}
		count = 0
	}
	s.q.SetLoginFailure(ctx, db.SetLoginFailureParams{ID: id.ID, FailedLogins: count, LockedUntil: lockedUntil})
}

type refreshRequest struct {
	RefreshToken    string `json:"refresh_token"`
	ClientPublicKey []byte `json:"client_public_key"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := s.readRequest(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.RefreshToken == "" {
		http.Error(w, "refresh_token is required", http.StatusBadRequest)
		return
	}
	if s.cfg.EncryptionEnabled && len(req.ClientPublicKey) == 0 {
		http.Error(w, "client_public_key is required", http.StatusBadRequest)
		return
	}

	pair, clientPublic, err := s.refresh(r.Context(), req)
	if errors.Is(err, errBadCredentials) {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	if err != nil {
		serverError(w, "refresh failed", err)
		return
	}
	s.writeResponse(w, clientPublic, pair)
}

// refresh validates the refresh token, rotates it (one-time use — the old token
// stops working), updates the session's client key, and mints a fresh access token.
func (s *Server) refresh(ctx context.Context, req refreshRequest) (tokenPair, []byte, error) {
	sess, err := s.q.GetSessionByTokenHash(ctx, HashToken(req.RefreshToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return tokenPair{}, nil, errBadCredentials
	}
	if err != nil {
		return tokenPair{}, nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return tokenPair{}, nil, err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)

	clientPublic := sess.ClientPublicKey
	if len(req.ClientPublicKey) > 0 {
		clientPublic = req.ClientPublicKey
		if err := q.UpdateSessionClientKey(ctx, db.UpdateSessionClientKeyParams{ID: sess.ID, ClientPublicKey: clientPublic}); err != nil {
			return tokenPair{}, nil, err
		}
	}

	rawRefresh, refreshHash, err := GenerateToken()
	if err != nil {
		return tokenPair{}, nil, err
	}
	if err := q.RotateSessionToken(ctx, db.RotateSessionTokenParams{ID: sess.ID, TokenHash: refreshHash}); err != nil {
		return tokenPair{}, nil, err
	}
	rawAccess, err := s.mintAccessToken(ctx, q, sess.ID)
	if err != nil {
		return tokenPair{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return tokenPair{}, nil, err
	}
	return tokenPair{AccessToken: rawAccess, RefreshToken: rawRefresh}, clientPublic, nil
}

func (s *Server) mintAccessToken(ctx context.Context, q *db.Queries, sessionID pgtype.UUID) (string, error) {
	raw, hash, err := GenerateToken()
	if err != nil {
		return "", err
	}
	_, err = q.CreateAccessToken(ctx, db.CreateAccessTokenParams{
		SessionID: sessionID,
		TokenHash: hash,
		ExpiresAt: expiry(accessTTL),
	})
	return raw, err
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.q.RevokeSession(r.Context(), authFrom(r.Context()).SessionID); err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func expiry(d time.Duration) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Now().Add(d), Valid: true}
}
