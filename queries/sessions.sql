-- name: CreateSession :one
insert into sessions (user_id, token_hash, client_public_key, expires_at)
values ($1, $2, $3, $4)
returning *;

-- name: GetSessionByTokenHash :one
select * from sessions
where token_hash = $1 and revoked_at is null and expires_at > now();

-- name: UpdateSessionClientKey :exec
update sessions set client_public_key = $2 where id = $1;

-- name: RotateSessionToken :exec
update sessions set token_hash = $2 where id = $1;

-- name: RevokeSession :exec
update sessions set revoked_at = now() where id = $1;

-- name: RevokeAllUserSessions :exec
update sessions set revoked_at = now() where user_id = $1 and revoked_at is null;
