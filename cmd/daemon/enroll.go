package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/tofunmiadewuyi/custos/internal/daemon"
)

func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	controlPlane := fs.String("control-plane", "", "control plane base URL")
	token := fs.String("token", "", "admin-issued enrollment token")
	hostname := fs.String("hostname", "", "host name to register (default: system hostname)")
	dir := fs.String("dir", daemon.DefaultDir, "state directory")
	fs.Parse(args)

	if *controlPlane == "" || *token == "" {
		fatal("enroll: --control-plane and --token are required")
	}
	host := *hostname
	if host == "" {
		h, err := os.Hostname()
		if err != nil {
			fatal("enroll: cannot determine hostname: %v", err)
		}
		host = h
	}

	store, err := daemon.OpenStore(*dir)
	if err != nil {
		fatal("enroll: %v", err)
	}
	if err := daemon.Enroll(context.Background(), store, daemon.EnrollOptions{
		ControlPlane: *controlPlane,
		Token:        *token,
		Hostname:     host,
	}); err != nil {
		fatal("enroll: %v", err)
	}
	fmt.Println("enrolled with control plane")
	fmt.Println("start the daemon with: sudo systemctl enable --now custosd")
}
