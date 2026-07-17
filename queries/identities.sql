-- name: GetIdentity :one
select * from identities where provider = $1 and external_id = $2;

-- name: CreateIdentity :one
insert into identities (user_id, provider, external_id, password_hash)
values ($1, $2, $3, $4)
returning *;

-- name: TouchIdentityLogin :exec
update identities set last_login_at = now() where id = $1;
