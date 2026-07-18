package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tofunmiadewuyi/custos/internal/controlplane"
)

func cmdServe(args []string) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg, err := controlplane.LoadConfig()
	if err != nil {
		fatal("serve: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := controlplane.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		fatal("serve: %v", err)
	}
	defer pool.Close()

	slog.Info("control plane listening", "addr", cfg.ListenAddr, "encryption", cfg.EncryptionEnabled)
	if err := controlplane.NewServer(cfg, pool).Serve(ctx); err != nil {
		fatal("serve: %v", err)
	}
}
