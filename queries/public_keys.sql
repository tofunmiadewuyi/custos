-- name: CreatePublicKey :one
insert into public_keys (user_id, label, key_type, key_blob, fingerprint)
values ($1, $2, $3, $4, $5)
returning *;

-- name: ListUserPublicKeys :many
select * from public_keys where user_id = $1 order by created_at;

-- name: DeletePublicKey :execrows
delete from public_keys where id = $1 and user_id = $2;
