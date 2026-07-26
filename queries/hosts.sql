-- name: CreateHost :one
insert into hosts (name, hostname, identity_key, accounts, machine_id)
values ($1, $2, $3, $4, $5)
returning *;

-- name: GetActiveHostByMachineID :one
select * from hosts where machine_id = $1 and status = 'active';

-- name: GetHostByID :one
select * from hosts where id = $1;

-- name: TouchHostSeen :exec
update hosts set last_seen_at = now() where id = $1;

-- name: SetHostStatus :execrows
update hosts set status = $2 where id = $1;

-- name: NextHostSeq :one
update hosts set last_seq = last_seq + 1 where id = $1 returning last_seq;

-- name: ListHosts :many
select id, name, hostname, accounts, status, enrolled_at, last_seen_at
from hosts order by name;
