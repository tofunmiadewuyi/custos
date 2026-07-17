package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
)

type Server struct {
	cfg  Config
	pool *pgxpool.Pool
	q    *db.Queries
}

func NewServer(cfg Config, pool *pgxpool.Pool) *Server {
	return &Server{cfg: cfg, pool: pool, q: db.New(pool)}
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	r.Post("/enroll", s.handleEnroll)
	r.Get("/daemon", s.handleDaemon)
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
