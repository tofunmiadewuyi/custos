package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"golang.org/x/time/rate"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/email"
	"github.com/tofunmiadewuyi/custos/internal/vault"
)

type Server struct {
	cfg     Config
	pool    *pgxpool.Pool
	q       *db.Queries
	hub     *hub
	wrapper vault.KeyWrapper // nil if no valid master key (secrets endpoints then 503)
	email   email.Sender
	authRL  *rateLimiter
}

func NewServer(cfg Config, pool *pgxpool.Pool) *Server {
	s := &Server{
		cfg:    cfg,
		pool:   pool,
		q:      db.New(pool),
		hub:    newHub(),
		email:  email.New(cfg.ResendAPIKey, cfg.EmailFrom),
		authRL: newRateLimiter(rate.Every(6*time.Second), 10), // ~10/min per IP, burst 10
	}
	if w, err := vault.NewAESWrapper(cfg.MasterKey); err == nil {
		s.wrapper = w
	}
	return s
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	r.Get("/daemon", s.handleDaemon)

	// Unauthenticated endpoints — rate-limited per IP against brute force.
	r.Group(func(r chi.Router) {
		r.Use(s.authRL.middleware)
		r.Post("/enroll", s.handleEnroll)
		r.Post("/login", s.handleLogin)
		r.Post("/refresh", s.handleRefresh)
		r.Post("/invitations/accept", s.handleAcceptInvitation)
		r.Post("/password-reset", s.handlePasswordReset)
		r.Post("/password-reset/confirm", s.handlePasswordResetConfirm)
	})

	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Get("/me", s.handleMe)
		r.Post("/logout", s.handleLogout)
		r.Post("/keys", s.handleAddKey)
		r.Get("/keys", s.handleListKeys)
		r.Delete("/keys/{id}", s.handleDeleteKey)
		r.Post("/secrets", s.handleCreateSecret)
		r.Get("/secrets", s.handleListSecrets)
		r.Get("/secrets/{id}", s.handleGetSecret)
		r.Get("/secrets/{id}/audit", s.handleSecretAudit)
		r.Put("/secrets/{id}", s.handleUpdateSecret)
		r.Delete("/secrets/{id}", s.handleDeleteSecret)
	})

	r.Group(func(r chi.Router) {
		r.Use(s.requireAdmin)
		r.Post("/enroll-tokens", s.handleCreateEnrollToken)
		r.Get("/hosts", s.handleListHosts)
		r.Get("/audit", s.handleAllAudit)

		r.Get("/users", s.handleListUsers)
		r.Post("/users/{id}/suspend", s.handleSuspendUser)
		r.Post("/users/{id}/activate", s.handleActivateUser)
		r.Delete("/users/{id}", s.handleRemoveUser)

		r.Post("/invitations", s.handleCreateInvitation)
		r.Get("/invitations", s.handleListInvitations)
		r.Delete("/invitations/{id}", s.handleCancelInvitation)
		r.Post("/invitations/{id}/resend", s.handleResendInvitation)

		r.Post("/groups", s.handleCreateGroup)
		r.Get("/groups", s.handleListGroups)
		r.Get("/groups/{id}", s.handleGetGroup)
		r.Delete("/groups/{id}", s.handleDeleteGroup)
		r.Post("/groups/{id}/resources", s.handleAddGroupResource)
		r.Delete("/groups/{id}/resources", s.handleRemoveGroupResource)

		r.Get("/grants", s.handleListGrants)
		r.Post("/grants", s.handleCreateGrant)
		r.Delete("/grants/{id}", s.handleRevokeGrant)
	})
	return r
}

// Serve runs the HTTP server until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{Addr: s.cfg.ListenAddr, Handler: s.Handler()}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
