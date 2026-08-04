-- name: CreateSet :one
insert into secret_sets (name, created_by) values ($1, $2) returning *;

-- name: GetSet :one
select * from secret_sets where id = $1;

-- name: UpdateSetName :one
update secret_sets set name = $2, updated_at = now() where id = $1 returning *;

-- name: ListSets :many
select ss.id, ss.name, ss.created_at, ss.updated_at, coalesce(k.key_count, 0)::bigint as key_count
from secret_sets ss
left join (
  select set_id, count(*) as key_count
  from secret_set_entries
  group by set_id
) k on k.set_id = ss.id
order by ss.name;

-- name: ListReadableSets :many
select distinct ss.id, ss.name, ss.created_at, ss.updated_at, coalesce(k.key_count, 0)::bigint as key_count
from secret_sets ss
join grants g on g.permission = 'set.read' and g.revoked_at is null
  and g.target_kind = 'set' and g.target_id = ss.id
left join (
  select set_id, count(*) as key_count
  from secret_set_entries
  group by set_id
) k on k.set_id = ss.id
where g.user_id = $1
order by ss.name;

-- name: CreateSetEntry :exec
insert into secret_set_entries (set_id, key, ciphertext, nonce, wrapped_key)
values ($1, $2, $3, $4, $5);

-- name: ListSetKeys :many
select key from secret_set_entries where set_id = $1 order by key;

-- name: GetSetEntries :many
select key, ciphertext, nonce, wrapped_key from secret_set_entries where set_id = $1 order by key;

-- name: BindSet :exec
insert into host_set_bindings (host_id, set_id, as_user, granted_by)
values ($1, $2, $3, $4)
on conflict (host_id, set_id) do update
  set as_user = excluded.as_user, granted_by = excluded.granted_by, revoked_at = null;

-- name: UnbindSet :execrows
delete from host_set_bindings where host_id = $1 and set_id = $2;

-- name: SetsForHost :many
select ss.id, ss.name, ss.updated_at, hsb.as_user
from host_set_bindings hsb
join secret_sets ss on ss.id = hsb.set_id
where hsb.host_id = $1 and hsb.revoked_at is null
order by ss.name;

-- name: HostsForSet :many
select host_id from host_set_bindings where set_id = $1 and revoked_at is null;

-- name: ListHostsForSet :many
select h.id, h.name, h.hostname, h.accounts, h.status, h.agent_version, h.desired_version,
       h.enrolled_at, h.last_seen_at, hsb.as_user, hsb.created_at as bound_at
from host_set_bindings hsb
join hosts h on h.id = hsb.host_id
where hsb.set_id = $1 and hsb.revoked_at is null
order by h.name;

-- name: DeleteSetEntries :exec
delete from secret_set_entries where set_id = $1;

-- name: UpsertSetEntry :exec
insert into secret_set_entries (set_id, key, ciphertext, nonce, wrapped_key)
values ($1, $2, $3, $4, $5)
on conflict (set_id, key) do update
  set ciphertext = excluded.ciphertext, nonce = excluded.nonce,
      wrapped_key = excluded.wrapped_key, updated_at = now();

-- name: DeleteSetEntry :execrows
delete from secret_set_entries where set_id = $1 and key = $2;

-- name: TouchSet :exec
update secret_sets set updated_at = now() where id = $1;

-- name: DeleteSet :execrows
delete from secret_sets where id = $1;

-- name: InsertSetAudit :exec
insert into set_audit_logs (set_name, entry_key, host_id, action, actor)
values ($1, $2, $3, $4, $5);

-- name: RenameSetAuditLogs :exec
update set_audit_logs set set_name = $2 where set_name = $1;

-- name: ListSetAudit :many
select a.action, a.set_name, a.entry_key, a.host_id, a.actor, u.email as actor_email,
       u.name as actor_name, u.display_name as actor_display_name, a.at
from set_audit_logs a
left join users u on u.id = a.actor
where a.set_name = $1
order by a.at desc
limit 100;
