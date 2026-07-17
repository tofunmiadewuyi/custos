-- name: GetPublicKeyByFingerprint :one
select * from public_keys where fingerprint = $1;

-- name: InsertSSHAccessLog :exec
insert into ssh_access_logs (host_id, public_key_id, account, allowed, at)
values ($1, $2, $3, $4, $5);
