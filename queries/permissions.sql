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
