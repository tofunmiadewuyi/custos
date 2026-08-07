-- name: GetPublicKeyByFingerprint :one
select * from public_keys where fingerprint = $1;

-- name: InsertSSHAccessLog :exec
insert into ssh_access_logs (host_id, hostname, public_key_id, account, allowed, at, fingerprint)
values ($1, $2, $3, $4, $5, $6, $7);

-- name: ListHostAccessLogs :many
-- Keyset pagination on (at, id) desc. Pass cursor_at/cursor_id null for the first page.
-- All filter args are nullable; a null arg disables that filter.
select l.id, l.account, l.allowed, l.fingerprint, l.at,
       u.id as user_id,
       coalesce(u.email, '') as user_email,
       coalesce(u.name, '') as user_name,
       coalesce(u.display_name, '') as user_display_name,
       coalesce(u.role, '') as user_role,
       coalesce(u.status, '') as user_status
from ssh_access_logs l
left join public_keys pk on pk.fingerprint = l.fingerprint
left join users u on u.id = pk.user_id
where l.host_id = @host_id
  and (
    sqlc.narg('cursor_at')::timestamptz is null
    or (l.at, l.id) < (sqlc.narg('cursor_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
  and (sqlc.narg('from')::timestamptz is null or l.at >= sqlc.narg('from')::timestamptz)
  and (sqlc.narg('to')::timestamptz is null or l.at <= sqlc.narg('to')::timestamptz)
  and (sqlc.narg('allowed')::boolean is null or l.allowed = sqlc.narg('allowed')::boolean)
  and (sqlc.narg('user_id')::uuid is null or u.id = sqlc.narg('user_id')::uuid)
  and (
    sqlc.narg('search')::text is null
    or l.account ilike '%' || sqlc.narg('search')::text || '%'
    or l.fingerprint ilike '%' || sqlc.narg('search')::text || '%'
    or u.email ilike '%' || sqlc.narg('search')::text || '%'
    or u.name ilike '%' || sqlc.narg('search')::text || '%'
  )
order by l.at desc, l.id desc
limit @page_limit;
