-- name: CreateGrant :one
insert into grants (user_id, permission, target_kind, target_id, granted_by)
values ($1, $2, $3, $4, $5)
returning *;

-- name: RevokeGrant :one
update grants set revoked_at = now()
where id = $1 and revoked_at is null
returning *;

-- name: GroupHostIDs :many
select resource_id from group_resources
where group_id = $1 and resource_kind = 'host';

-- name: ListGrants :many
select g.id, g.permission, g.target_kind, g.target_id, g.created_at,
       u.id as user_id, u.email as user_email
from grants g
join users u on u.id = g.user_id
where g.revoked_at is null
order by g.created_at desc;

-- name: InsertGrantAudit :exec
insert into grant_audit_logs
  (action, grant_id, actor_id, actor_email, subject_id, subject_email, permission, target_kind, target_id)
values ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListGrantAudit :many
select id, action, grant_id, actor_id, actor_email, subject_id, subject_email,
       permission, target_kind, target_id, at
from grant_audit_logs
order by at desc
limit 100;
