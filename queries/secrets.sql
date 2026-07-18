-- name: CreateSecret :one
insert into secrets (name, ciphertext, nonce, wrapped_key, created_by)
values ($1, $2, $3, $4, $5)
returning *;

-- name: GetSecret :one
select * from secrets where id = $1;

-- name: UpdateSecret :one
update secrets set ciphertext = $2, nonce = $3, wrapped_key = $4, updated_at = now()
where id = $1
returning *;

-- name: DeleteSecret :exec
delete from secrets where id = $1;

-- name: ListAllSecrets :many
select id, name, created_at, updated_at from secrets order by name;

-- name: ListReadableSecrets :many
select distinct s.id, s.name, s.created_at, s.updated_at
from secrets s
join grants g on g.permission = 'secret.read' and g.revoked_at is null
  and (
    (g.target_kind = 'secret' and g.target_id = s.id)
    or (g.target_kind = 'group' and g.target_id in (
      select group_id from group_resources
      where resource_kind = 'secret' and resource_id = s.id))
  )
where g.user_id = $1
order by s.name;

-- name: InsertSecretAudit :exec
insert into secret_audit_logs (secret_id, secret_name, action, user_id)
values ($1, $2, $3, $4);

-- name: ListSecretAudit :many
select a.id, a.action, a.at, a.secret_id, a.secret_name, u.id as user_id, u.email as user_email
from secret_audit_logs a
left join users u on u.id = a.user_id
where a.secret_id = $1
order by a.at desc;

-- name: ListAllSecretAudit :many
select a.id, a.action, a.at, a.secret_id, a.secret_name, u.id as user_id, u.email as user_email
from secret_audit_logs a
left join users u on u.id = a.user_id
order by a.at desc
limit $1;
