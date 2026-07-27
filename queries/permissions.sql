-- name: UserHasGlobalPermission :one
select exists (
  select 1 from grants
  where user_id = @user_id and permission = @permission
    and target_kind = 'global' and revoked_at is null
);

-- name: UserHasSecretPermission :one
select exists (
  select 1 from grants g
  where g.user_id = @user_id and g.permission = @permission and g.revoked_at is null
    and (
      (g.target_kind = 'secret' and g.target_id = @secret_id)
      or (g.target_kind = 'group' and g.target_id in (
        select group_id from group_resources
        where resource_kind = 'secret' and resource_id = @secret_id))
    )
);

-- name: ListSecretDirectAccess :many
select u.id as user_id, u.email, u.name, u.role, u.status, g.permission, g.created_at
from grants g
join users u on u.id = g.user_id
where g.revoked_at is null
  and g.target_kind = 'secret' and g.target_id = @secret_id
order by u.email;

-- name: ListSecretGroupAccess :many
select u.id as user_id, u.email, u.name, u.role, u.status, g.permission, g.created_at,
       rg.id as group_id, rg.name as group_name
from grants g
join users u on u.id = g.user_id
join resource_groups rg on rg.id = g.target_id
where g.revoked_at is null
  and g.target_kind = 'group'
  and rg.id in (
    select group_id from group_resources
    where resource_kind = 'secret' and resource_id = @secret_id
  )
order by rg.name, u.email;

-- name: UserHasGroupPermission :one
select exists (
  select 1 from grants
  where user_id = @user_id and permission = @permission and revoked_at is null
    and target_kind = 'group' and target_id = @group_id
);

-- name: UserHasSetPermission :one
select exists (
  select 1 from grants
  where user_id = @user_id and permission = @permission and revoked_at is null
    and target_kind = 'set' and target_id = @set_id
);

-- name: ListActiveAdmins :many
select id as user_id, email, name, status from users
where role = 'admin' and status = 'active'
order by email;
