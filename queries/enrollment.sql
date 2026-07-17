-- name: GetEnrollmentToken :one
select * from enrollment_tokens where token_hash = $1;

-- name: CreateEnrollmentToken :one
insert into enrollment_tokens (token_hash, label, accounts, created_by, expires_at)
values ($1, $2, $3, $4, $5)
returning *;

-- name: MarkTokenUsed :exec
update enrollment_tokens set used_at = now(), host_id = $2 where id = $1;
