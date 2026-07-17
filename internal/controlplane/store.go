package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/password"
)

// ErrEmailTaken is returned when creating a user whose email already exists.
var ErrEmailTaken = errors.New("a user with that email already exists")

// Connect opens a pgx connection pool and verifies it reaches the database.
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// CreateAdmin creates an admin user with a password identity, transactionally.
func CreateAdmin(ctx context.Context, pool *pgxpool.Pool, email, plainPassword string) error {
	hash, err := password.Hash(plainPassword)
	if err != nil {
		return err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)

	user, err := q.CreateUser(ctx, db.CreateUserParams{Email: email, Name: "Admin", Role: "admin"})
	if err != nil {
		if isUniqueViolation(err) {
			return ErrEmailTaken
		}
		return fmt.Errorf("create admin user: %w", err)
	}
	if _, err := q.CreateIdentity(ctx, db.CreateIdentityParams{
		UserID:       user.ID,
		Provider:     "password",
		ExternalID:   email,
		PasswordHash: pgtype.Text{String: hash, Valid: true},
	}); err != nil {
		return fmt.Errorf("create admin identity: %w", err)
	}
	return tx.Commit(ctx)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
