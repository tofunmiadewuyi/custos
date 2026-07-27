package controlplane

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"

	"golang.org/x/time/rate"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/email"
	"github.com/tofunmiadewuyi/custos/internal/identity"
	"github.com/tofunmiadewuyi/custos/internal/vault"
)

type Server struct {
	cfg     Config
	pool    *pgxpool.Pool
	q       *db.Queries
	hub     *hub
	wrapper vault.KeyWrapper // nil if no valid master key (secrets endpoints then 503)
	signer  *identity.KeyPair
	email   email.Sender
	authRL  *rateLimiter

	checksumMu sync.Mutex
	checksums  map[string]map[string]string // version -> arch -> tarball digest
}

func NewServer(cfg Config, pool *pgxpool.Pool) *Server {
	s := &Server{
		cfg:    cfg,
		pool:   pool,
		q:      db.New(pool),
		hub:    newHub(),
		email:     email.New(cfg.ResendAPIKey, cfg.EmailFrom),
		authRL:    newRateLimiter(rate.Every(6*time.Second), 10), // ~10/min per IP, burst 10
		checksums: map[string]map[string]string{},
	}
	if w, err := vault.NewAESWrapper(cfg.MasterKey); err == nil {
		s.wrapper = w
	}
	if kp, err := identity.LoadKeyPair(cfg.SigningKey); err == nil {
		s.signer = kp
	}
	return s
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(s.corsMiddleware())

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
		r.Patch("/me", s.handleUpdateProfile)
		r.Post("/logout", s.handleLogout)

		r.Post("/keys", s.handleAddKey)
		r.Get("/keys", s.handleListKeys)
		r.Delete("/keys/{id}", s.handleDeleteKey)

		r.Post("/secrets", s.handleCreateSecret)
		r.Get("/secrets", s.handleListSecrets)
		r.Get("/secrets/{id}", s.handleGetSecret)
		r.Get("/secrets/{id}/reveal", s.handleRevealSecret)
		r.Get("/secrets/{id}/audit", s.handleSecretAudit)
		r.Put("/secrets/{id}", s.handleUpdateSecret)
		r.Delete("/secrets/{id}", s.handleDeleteSecret)

		// Groups and sets self-gate per-handler via grants (canGlobal/canGroup/canSet).
		r.Post("/groups", s.handleCreateGroup)
		r.Get("/groups", s.handleListGroups)
		r.Get("/groups/{id}", s.handleGetGroup)
		r.Delete("/groups/{id}", s.handleDeleteGroup)
		r.Post("/groups/{id}/resources", s.handleAddGroupResource)
		r.Delete("/groups/{id}/resources", s.handleRemoveGroupResource)

		r.Post("/sets", s.handleCreateSet)
		r.Get("/sets", s.handleListSets)
		r.Get("/sets/{id}", s.handleGetSet)
		r.Get("/sets/{id}/audit", s.handleSetAudit)
		r.Put("/sets/{id}", s.handleUpdateSet)
		r.Delete("/sets/{id}", s.handleDeleteSet)
		r.Post("/hosts/{id}/sets", s.handleBindSet)
		r.Delete("/hosts/{id}/sets/{setId}", s.handleUnbindSet)
	})

	r.Group(func(r chi.Router) {
		r.Use(s.requireAdmin)
		r.Post("/enroll-tokens", s.handleCreateEnrollToken)
		r.Get("/hosts", s.handleListHosts)
		r.Post("/hosts/{id}/revoke", s.handleRevokeHost)
		r.Post("/hosts/{id}/upgrade", s.handleUpgradeHost)
		r.Post("/upgrade", s.handleUpgradeFleet)
		r.Get("/audit", s.handleAllAudit)
		r.Get("/grant-audit", s.handleGrantAudit)

		r.Get("/users", s.handleListUsers)
		r.Post("/users/{id}/suspend", s.handleSuspendUser)
		r.Post("/users/{id}/activate", s.handleActivateUser)
		r.Delete("/users/{id}", s.handleRemoveUser)

		r.Post("/invitations", s.handleCreateInvitation)
		r.Get("/invitations", s.handleListInvitations)
		r.Delete("/invitations/{id}", s.handleCancelInvitation)
		r.Post("/invitations/{id}/resend", s.handleResendInvitation)

		r.Get("/grants", s.handleListGrants)
		r.Post("/grants", s.handleCreateGrant)
		r.Delete("/grants/{id}", s.handleRevokeGrant)

		r.Get("/secrets/{id}/access-audit", s.handleSecretAccessAudit)
	})
	return r
}

func (s *Server) corsMiddleware() func(http.Handler) http.Handler {
	origins := s.cfg.CorsOrigins
	if len(origins) == 0 {
		origins = []string{"*"}
	}
	return cors.Handler(cors.Options{
		AllowedOrigins: origins,
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		MaxAge:         300,
	})
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
