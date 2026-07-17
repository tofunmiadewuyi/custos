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
	sshUser := fs.String("ssh-user", "custos", "AuthorizedKeysCommandUser")
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

	setupSSHD(*sshUser)
}

func setupSSHD(sshUser string) {
	binaryPath, err := os.Executable()
	if err != nil {
		fatal("enroll: cannot resolve own path: %v", err)
	}

	if ok, err := daemon.HasInclude(""); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot read sshd_config: %v\n", err)
	} else if !ok {
		fmt.Fprintln(os.Stderr, "warning: sshd_config does not include the drop-in dir; add this line and reload sshd:")
		fmt.Fprintln(os.Stderr, "  Include /etc/ssh/sshd_config.d/*.conf")
	}

	path, err := daemon.WriteDropIn("", binaryPath, sshUser)
	if err != nil {
		fatal("enroll: write sshd drop-in: %v", err)
	}
	if err := daemon.Validate(); err != nil {
		daemon.RemoveDropIn("")
		fatal("enroll: sshd config invalid, rolled back: %v", err)
	}
	if err := daemon.Reload(); err != nil {
		fmt.Fprintf(os.Stderr, "wrote and validated %s, but reload failed; reload sshd manually: %v\n", path, err)
		return
	}
	fmt.Println("sshd configured:", path)
}

