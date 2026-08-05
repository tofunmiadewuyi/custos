-- name: UserHasGlobalPermission :one
select exists (
  select 1 from grants
  where user_id = @user_id and permission = @permission
    and target_kind = 'global' and revoked_at is null
);

-- name: ListUserGlobalPermissions :many
select g.id as grant_id, p.key as permission, p.description, g.created_at as granted_at
from grants g
join permissions p on p.key = g.permission
where g.user_id = @user_id
  and g.target_kind = 'global'
  and g.revoked_at is null
order by p.key;

-- name: ListGlobalPermissions :many
select key as permission, description
from permissions
where key in ('secret.add', 'group.create', 'set.add')
order by key;

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
select u.id as user_id, u.email, u.name, u.display_name, u.role, u.status, g.permission, g.created_at
from grants g
join users u on u.id = g.user_id
where g.revoked_at is null
  and g.target_kind = 'secret' and g.target_id = @secret_id
order by u.email;

-- name: ListSecretGroupAccess :many
select u.id as user_id, u.email, u.name, u.display_name, u.role, u.status, g.permission, g.created_at,
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

-- name: UserHasHostPermission :one
select exists (
  select 1 from grants g
  where g.user_id = @user_id and g.permission = @permission and g.revoked_at is null
    and (
      (g.target_kind = 'host' and g.target_id = @host_id)
      or (g.target_kind = 'group' and g.target_id in (
        select group_id from group_resources
        where resource_kind = 'host' and resource_id = @host_id))
    )
);

-- name: UserHasSetPermission :one
select exists (
  select 1 from grants g
  where g.user_id = @user_id and g.permission = @permission and g.revoked_at is null
    and (
      (g.target_kind = 'set' and g.target_id = @set_id)
      or (g.target_kind = 'group' and g.target_id in (
        select group_id from group_resources
        where resource_kind = 'set' and resource_id = @set_id))
    )
);

-- name: ListHostDirectAccess :many
select u.id as user_id, u.email, u.name, u.display_name, u.role, u.status, g.permission, g.created_at
from grants g
join users u on u.id = g.user_id
where g.revoked_at is null
  and g.permission = 'host.access'
  and g.target_kind = 'host' and g.target_id = @host_id
order by u.email;

-- name: ListHostGroupAccess :many
select u.id as user_id, u.email, u.name, u.display_name, u.role, u.status, g.permission, g.created_at,
       rg.id as group_id, rg.name as group_name
from grants g
join users u on u.id = g.user_id
join resource_groups rg on rg.id = g.target_id
where g.revoked_at is null
  and g.permission = 'host.access'
  and g.target_kind = 'group'
  and rg.id in (
    select group_id from group_resources
    where resource_kind = 'host' and resource_id = @host_id
  )
order by rg.name, u.email;

-- name: ListActiveAdmins :many
select id as user_id, email, name, display_name, status from users
where role = 'admin' and status = 'active'
order by email;
