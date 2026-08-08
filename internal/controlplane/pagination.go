package controlplane

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

const (
	defaultPageSize = 10
	maxPageSize     = 100
)

// page is the envelope for every paginated audit response. NextCursor is empty
// when there are no more rows.
type page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// atCursor is a keyset cursor over rows ordered by (at, id) desc.
type atCursor struct {
	At pgtype.Timestamptz
	ID pgtype.UUID
}

// userCursor is a keyset cursor over rows ordered by (email, user_id) asc.
type userCursor struct {
	Email string
	ID    pgtype.UUID
}

// pageParams parses ?limit and ?cursor. A missing/blank cursor yields a zero
// (null) atCursor, which the queries treat as the first page.
func pageParams(r *http.Request) (limit int32, cur atCursor, err error) {
	limit = defaultPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 {
			return 0, atCursor{}, errors.New("invalid limit")
		}
		if n > maxPageSize {
			n = maxPageSize
		}
		limit = int32(n)
	}
	cur, err = decodeCursor(r.URL.Query().Get("cursor"))
	return limit, cur, err
}

func userPageParams(r *http.Request) (limit int32, cur userCursor, err error) {
	limit = defaultPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 {
			return 0, userCursor{}, errors.New("invalid limit")
		}
		if n > maxPageSize {
			n = maxPageSize
		}
		limit = int32(n)
	}
	cur, err = decodeUserCursor(r.URL.Query().Get("cursor"))
	return limit, cur, err
}

// auditFilters holds the optional filters shared across audit endpoints. A zero
// (invalid) field means the filter is disabled.
type auditFilters struct {
	From    pgtype.Timestamptz
	To      pgtype.Timestamptz
	Allowed pgtype.Bool
	UserID  pgtype.UUID
	Search  pgtype.Text
}

// parseAuditFilters reads ?from, ?to (RFC3339), ?success (true|false), ?user_id,
// and ?q from the request.
func parseAuditFilters(r *http.Request) (auditFilters, error) {
	q := r.URL.Query()
	var f auditFilters
	var err error
	if f.From, err = parseTimeParam(q.Get("from")); err != nil {
		return auditFilters{}, errors.New("invalid from")
	}
	if f.To, err = parseTimeParam(q.Get("to")); err != nil {
		return auditFilters{}, errors.New("invalid to")
	}
	if raw := q.Get("success"); raw != "" {
		b, e := strconv.ParseBool(raw)
		if e != nil {
			return auditFilters{}, errors.New("invalid success")
		}
		f.Allowed = pgtype.Bool{Bool: b, Valid: true}
	}
	if raw := q.Get("user_id"); raw != "" {
		id, e := parseUUID(raw)
		if e != nil {
			return auditFilters{}, errors.New("invalid user_id")
		}
		f.UserID = id
	}
	if raw := strings.TrimSpace(q.Get("q")); raw != "" {
		f.Search = pgtype.Text{String: raw, Valid: true}
	}
	return f, nil
}

func parseTimeParam(raw string) (pgtype.Timestamptz, error) {
	if raw == "" {
		return pgtype.Timestamptz{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return pgtype.Timestamptz{}, err
	}
	return pgtype.Timestamptz{Time: t, Valid: true}, nil
}

// encodeCursor renders "<RFC3339Nano>|<uuid>" as base64url.
func encodeCursor(at pgtype.Timestamptz, id pgtype.UUID) string {
	s := at.Time.UTC().Format(time.RFC3339Nano) + "|" + uuidString(id)
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func decodeCursor(raw string) (atCursor, error) {
	if raw == "" {
		return atCursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return atCursor{}, errors.New("invalid cursor")
	}
	at, id, ok := strings.Cut(string(b), "|")
	if !ok {
		return atCursor{}, errors.New("invalid cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return atCursor{}, errors.New("invalid cursor")
	}
	uid, err := parseUUID(id)
	if err != nil {
		return atCursor{}, errors.New("invalid cursor")
	}
	return atCursor{At: pgtype.Timestamptz{Time: t, Valid: true}, ID: uid}, nil
}

func encodeUserCursor(email string, id pgtype.UUID) string {
	s := email + "\x00" + uuidString(id)
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func decodeUserCursor(raw string) (userCursor, error) {
	if raw == "" {
		return userCursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return userCursor{}, errors.New("invalid cursor")
	}
	email, id, ok := strings.Cut(string(b), "\x00")
	if !ok || email == "" {
		return userCursor{}, errors.New("invalid cursor")
	}
	uid, err := parseUUID(id)
	if err != nil {
		return userCursor{}, errors.New("invalid cursor")
	}
	return userCursor{Email: email, ID: uid}, nil
}
