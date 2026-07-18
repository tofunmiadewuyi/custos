package main

import (
	"context"
	"database/sql"
	"flag"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/tofunmiadewuyi/custos/migrations"
)

// cmdMigrate runs goose migrations from the embedded FS: `migrate` (up),
// `migrate down`, `migrate status`, etc.
func cmdMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dbURL := fs.String("database-url", os.Getenv("CUSTOS_DATABASE_URL"), "postgres connection url")
	fs.Parse(args)

	command := "up"
	if rest := fs.Args(); len(rest) > 0 {
		command = rest[0]
	}
	if *dbURL == "" {
		fatal("migrate: --database-url or CUSTOS_DATABASE_URL is required")
	}

	db, err := sql.Open("pgx", *dbURL)
	if err != nil {
		fatal("migrate: %v", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		fatal("migrate: %v", err)
	}
	if err := goose.RunContext(context.Background(), command, db, "."); err != nil {
		fatal("migrate: %v", err)
	}
}
