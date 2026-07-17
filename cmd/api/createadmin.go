package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/tofunmiadewuyi/custos/internal/controlplane"
)

func cmdCreateAdmin(args []string) {
	fs := flag.NewFlagSet("create-admin", flag.ExitOnError)
	email := fs.String("email", "", "admin email")
	pw := fs.String("password", "", "admin password (generated if empty)")
	dbURL := fs.String("database-url", os.Getenv("CUSTOS_DATABASE_URL"), "postgres connection url")
	fs.Parse(args)

	if *email == "" {
		fatal("create-admin: --email is required")
	}
	if *dbURL == "" {
		fatal("create-admin: --database-url or CUSTOS_DATABASE_URL is required")
	}

	password, generated := *pw, false
	if password == "" {
		password, generated = randomPassword(), true
	}

	ctx := context.Background()
	pool, err := controlplane.Connect(ctx, *dbURL)
	if err != nil {
		fatal("create-admin: %v", err)
	}
	defer pool.Close()

	if err := controlplane.CreateAdmin(ctx, pool, *email, password); err != nil {
		if errors.Is(err, controlplane.ErrEmailTaken) {
			fatal("create-admin: %s already exists", *email)
		}
		fatal("create-admin: %v", err)
	}

	fmt.Printf("admin created: %s\n", *email)
	if generated {
		fmt.Printf("password: %s\n", password)
	}
}

func randomPassword() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		fatal("create-admin: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
