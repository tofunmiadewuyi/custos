-- name: GetUserByEmail :one
select * from users where email = $1;

-- name: GetUserByID :one
select * from users where id = $1;

-- name: CreateUser :one
insert into users (email, name, role)
values ($1, $2, $3)
returning *;

-- name: CountActiveAdmins :one
select count(*) from users where role = 'admin' and status = 'active';

-- name: ListUsers :many
select id, email, name, role, status, created_at from users order by email;

-- name: SetUserStatus :execrows
update users set status = $2 where id = $1;

-- name: DeleteUserIdentities :exec
delete from identities where user_id = $1;

-- name: RevokeAllUserGrants :exec
update grants set revoked_at = now() where user_id = $1 and revoked_at is null;

-- name: UserGrantedHostIDs :many
select distinct h.id
from hosts h
join grants g on g.user_id = $1 and g.permission = 'host.access' and g.revoked_at is null
  and (
    (g.target_kind = 'host' and g.target_id = h.id)
    or (g.target_kind = 'group' and g.target_id in (
      select group_id from group_resources where resource_kind = 'host' and resource_id = h.id))
  );
