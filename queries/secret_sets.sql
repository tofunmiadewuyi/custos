-- name: CreateSet :one
insert into secret_sets (name, created_by) values ($1, $2) returning *;

-- name: GetSet :one
select * from secret_sets where id = $1;

-- name: ListSets :many
select id, name, created_at, updated_at from secret_sets order by name;

-- name: ListReadableSets :many
select distinct ss.id, ss.name, ss.created_at, ss.updated_at
from secret_sets ss
join grants g on g.permission = 'set.read' and g.revoked_at is null
  and g.target_kind = 'set' and g.target_id = ss.id
where g.user_id = $1
order by ss.name;

-- name: CreateSetEntry :exec
insert into secret_set_entries (set_id, key, ciphertext, nonce, wrapped_key)
values ($1, $2, $3, $4, $5);

-- name: ListSetKeys :many
select key from secret_set_entries where set_id = $1 order by key;

-- name: DeleteSetEntries :exec
delete from secret_set_entries where set_id = $1;

-- name: TouchSet :exec
update secret_sets set updated_at = now() where id = $1;

-- name: DeleteSet :execrows
delete from secret_sets where id = $1;

-- name: InsertSetAudit :exec
insert into set_audit_logs (set_name, entry_key, host_id, action, actor)
values ($1, $2, $3, $4, $5);
