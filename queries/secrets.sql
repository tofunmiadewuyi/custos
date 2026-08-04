-- name: CreateSecret :one
insert into secrets (label, url, username, otp_recipient, ciphertext, nonce, wrapped_key, created_by, updated_by)
values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
returning *;

-- name: GetSecret :one
select s.*,
       cu.name as created_by_name, cu.display_name as created_by_display_name, cu.email as created_by_email,
       uu.name as updated_by_name, uu.display_name as updated_by_display_name, uu.email as updated_by_email
from secrets s
left join users cu on cu.id = s.created_by
left join users uu on uu.id = s.updated_by
where s.id = $1;

-- name: UpdateSecret :one
update secrets set label = $2, url = $3, username = $4, otp_recipient = $5,
  ciphertext = $6, nonce = $7, wrapped_key = $8, updated_by = $9, updated_at = now()
where id = $1
returning *;

-- name: DeleteSecret :exec
delete from secrets where id = $1;

-- name: ListAllSecrets :many
select s.id, s.label, s.url, s.username, s.otp_recipient, s.created_at, s.updated_at,
       s.created_by, cu.name as created_by_name, cu.display_name as created_by_display_name, cu.email as created_by_email,
       s.updated_by, uu.name as updated_by_name, uu.display_name as updated_by_display_name, uu.email as updated_by_email
from secrets s
left join users cu on cu.id = s.created_by
left join users uu on uu.id = s.updated_by
order by s.label;

-- name: ListReadableSecrets :many
select distinct s.id, s.label, s.url, s.username, s.otp_recipient, s.created_at, s.updated_at,
       s.created_by, cu.name as created_by_name, cu.display_name as created_by_display_name, cu.email as created_by_email,
       s.updated_by, uu.name as updated_by_name, uu.display_name as updated_by_display_name, uu.email as updated_by_email
from secrets s
join grants g on g.permission = 'secret.read' and g.revoked_at is null
  and (
    (g.target_kind = 'secret' and g.target_id = s.id)
    or (g.target_kind = 'group' and g.target_id in (
      select group_id from group_resources where resource_kind = 'secret' and resource_id = s.id))
  )
left join users cu on cu.id = s.created_by
left join users uu on uu.id = s.updated_by
where g.user_id = $1
order by s.label;

-- name: InsertSecretAudit :exec
insert into secret_audit_logs (secret_id, secret_name, action, user_id)
values ($1, $2, $3, $4);

-- name: ListSecretAudit :many
select a.id, a.action, a.at, a.secret_id, a.secret_name, u.id as user_id,
       u.email as user_email, u.name as user_name, u.display_name as user_display_name
from secret_audit_logs a
left join users u on u.id = a.user_id
where a.secret_id = $1
order by a.at desc;

-- name: ListAllSecretAudit :many
select a.id, a.action, a.at, a.secret_id, a.secret_name, u.id as user_id,
       u.email as user_email, u.name as user_name, u.display_name as user_display_name
from secret_audit_logs a
left join users u on u.id = a.user_id
order by a.at desc
limit $1;
