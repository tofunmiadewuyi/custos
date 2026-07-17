package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/tofunmiadewuyi/custos/internal/controlplane"
)

func cmdServe(args []string) {
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

	log.Printf("control plane listening on %s", cfg.ListenAddr)
	if err := controlplane.NewServer(cfg, pool).Serve(ctx); err != nil {
		fatal("serve: %v", err)
	}
}
