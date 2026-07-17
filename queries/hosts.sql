-- name: CreateHost :one
insert into hosts (name, hostname, identity_key, accounts)
values ($1, $2, $3, $4)
returning *;

-- name: GetHostByID :one
select * from hosts where id = $1;

-- name: TouchHostSeen :exec
update hosts set last_seen_at = now() where id = $1;
