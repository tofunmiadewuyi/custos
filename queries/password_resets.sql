-- name: CreatePasswordReset :one
insert into password_resets (user_id, token_hash, expires_at)
values ($1, $2, $3)
returning *;

-- name: GetPasswordReset :one
select * from password_resets where token_hash = $1;

-- name: MarkPasswordResetUsed :exec
update password_resets set used_at = now() where id = $1;
