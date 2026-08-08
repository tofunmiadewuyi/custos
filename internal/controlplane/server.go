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
		cfg:       cfg,
		pool:      pool,
		q:         db.New(pool),
		hub:       newHub(),
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

	r.Group(s.publicRoutes) // unauthenticated, rate-limited
	r.Group(s.userRoutes)   // any valid session
	r.Group(s.adminRoutes)  // admin only
	return r
}

// publicRoutes are unauthenticated and rate-limited per IP against brute force.
func (s *Server) publicRoutes(r chi.Router) {
	r.Use(s.authRL.middleware)
	r.Post("/enroll", s.handleEnroll)
	r.Post("/hosts/{id}/decommission", s.handleDecommissionHost)
	r.Post("/login", s.handleLogin)
	r.Post("/refresh", s.handleRefresh)
	r.Post("/invitations/accept", s.handleAcceptInvitation)
	r.Route("/password-reset", func(r chi.Router) {
		r.Post("/", s.handlePasswordReset)
		r.Post("/confirm", s.handlePasswordResetConfirm)
	})
}

// userRoutes require a valid session. Secrets, groups, and sets self-gate per
// handler via grants (canGlobal/canSecret/canGroup/canSet); admins bypass.
func (s *Server) userRoutes(r chi.Router) {
	r.Use(s.requireAuth)
	r.Get("/me", s.handleMe)
	r.Patch("/me", s.handleUpdateProfile)
	r.Post("/logout", s.handleLogout)
	r.Post("/enroll-tokens", s.handleCreateEnrollToken)

	r.Route("/keys", func(r chi.Router) {
		r.Post("/", s.handleAddKey)
		r.Get("/", s.handleListKeys)
		r.Delete("/{id}", s.handleDeleteKey)
	})

	// /secrets stays flat: /secrets/{id}/access-audit is admin-only (spans tiers).
	r.Post("/secrets", s.handleCreateSecret)
	r.Get("/secrets", s.handleListSecrets)
	r.Get("/secrets/{id}", s.handleGetSecret)
	r.Get("/secrets/{id}/reveal", s.handleRevealSecret)
	r.Get("/secrets/{id}/audit", s.handleSecretAudit)
	r.Put("/secrets/{id}", s.handleUpdateSecret)
	r.Delete("/secrets/{id}", s.handleDeleteSecret)

	r.Route("/groups", func(r chi.Router) {
		r.Post("/", s.handleCreateGroup)
		r.Get("/", s.handleListGroups)
		r.Get("/resources/{kind}/{resourceID}", s.handleListGroupsForResource)
		r.Get("/{id}/members", s.handleListGroupMembers)
		r.Get("/{id}", s.handleGetGroup)
		r.Put("/{id}", s.handleUpdateGroup)
		r.Delete("/{id}", s.handleDeleteGroup)
		r.Post("/{id}/resources", s.handleAddGroupResource)
		r.Delete("/{id}/resources", s.handleRemoveGroupResource)
	})

	r.Route("/sets", func(r chi.Router) {
		r.Post("/", s.handleCreateSet)
		r.Get("/", s.handleListSets)
		r.Get("/{id}", s.handleGetSet)
		r.Get("/{id}/hosts", s.handleListSetHosts)
		r.Get("/{id}/audit", s.handleSetAudit)
		r.Put("/{id}", s.handleUpdateSet)
		r.Delete("/{id}", s.handleDeleteSet)
		r.Put("/{id}/entries/{key}", s.handleUpsertSetEntry)
		r.Delete("/{id}/entries/{key}", s.handleDeleteSetEntry)
	})

	// Host list/detail/audit, lifecycle actions, and set binding are self-gated by grants.
	r.Get("/hosts", s.handleListHosts)
	r.Get("/hosts/{id}", s.handleGetHost)
	r.Get("/hosts/{id}/audit", s.handleHostAudit)
	r.Get("/hosts/{id}/access-audit", s.handleHostAccessAudit)
	r.Post("/hosts/{id}/refresh", s.handleRefreshHost)
	r.Post("/hosts/{id}/revoke", s.handleRevokeHost)
	r.Post("/hosts/{id}/upgrade", s.handleUpgradeHost)
	r.Post("/hosts/{id}/sets", s.handleBindSet)
	r.Delete("/hosts/{id}/sets/{setId}", s.handleUnbindSet)
}

// adminRoutes require an admin session.
func (s *Server) adminRoutes(r chi.Router) {
	r.Use(s.requireAdmin)
	r.Post("/upgrade", s.handleUpgradeFleet)
	r.Get("/audit", s.handleAllAudit)
	r.Get("/grant-audit", s.handleGrantAudit)
	r.Get("/secrets/{id}/access-audit", s.handleSecretAccessAudit)

	// /hosts and /invitations stay flat: each spans tiers (/hosts/{id}/sets is user, /invitations/accept is public).

	r.Post("/invitations", s.handleCreateInvitation)
	r.Get("/invitations", s.handleListInvitations)
	r.Delete("/invitations/{id}", s.handleCancelInvitation)
	r.Post("/invitations/{id}/resend", s.handleResendInvitation)

	r.Route("/users", func(r chi.Router) {
		r.Get("/", s.handleListUsers)
		r.Post("/{id}/suspend", s.handleSuspendUser)
		r.Post("/{id}/activate", s.handleActivateUser)
		r.Delete("/{id}", s.handleRemoveUser)
	})

	r.Route("/grants", func(r chi.Router) {
		r.Get("/", s.handleListGrants)
		r.Post("/", s.handleCreateGrant)
		r.Delete("/{id}", s.handleRevokeGrant)
	})
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
