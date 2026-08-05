-- name: CreateHost :one
insert into hosts (name, hostname, identity_key, accounts, machine_id, encryption_key)
values ($1, $2, $3, $4, $5, $6)
returning *;

-- name: GetActiveHostByMachineID :one
select * from hosts where machine_id = $1 and status = 'active';

-- name: GetHostByID :one
select * from hosts where id = $1;

-- name: TouchHostSeen :exec
update hosts set last_seen_at = now() where id = $1;

-- name: SetHostStatus :execrows
update hosts set status = $2 where id = $1;

-- name: SetHostVersion :exec
update hosts set agent_version = $2 where id = $1;

-- name: SetHostDesiredVersion :exec
update hosts set desired_version = $2 where id = $1;

-- name: NextHostSeq :one
update hosts set last_seq = last_seq + 1 where id = $1 returning last_seq;

-- name: NextHostSetSeq :one
update hosts set last_set_seq = last_set_seq + 1 where id = $1 returning last_set_seq;

-- name: ListHosts :many
select id, name, hostname, accounts, status, agent_version, desired_version, enrolled_at, last_seen_at
from hosts
where status = 'active'
order by name;

-- name: ListReadableHosts :many
select distinct h.id, h.name, h.hostname, h.accounts, h.status, h.agent_version, h.desired_version,
       h.enrolled_at, h.last_seen_at
from hosts h
join grants g on g.user_id = $1 and g.permission = 'host.access' and g.revoked_at is null
  and (
    (g.target_kind = 'host' and g.target_id = h.id)
    or (g.target_kind = 'group' and g.target_id in (
      select group_id from group_resources where resource_kind = 'host' and resource_id = h.id))
  )
where h.status = 'active'
order by h.name;

-- name: ListActiveHosts :many
select id, name, hostname, agent_version, desired_version from hosts
where status = 'active' order by name;
