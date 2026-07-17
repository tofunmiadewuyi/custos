-- name: HostAccessKeys :many
select distinct pk.user_id, pk.key_type, pk.key_blob, pk.fingerprint
from grants g
join public_keys pk on pk.user_id = g.user_id
where g.permission = 'host.access'
  and g.revoked_at is null
  and (
    (g.target_kind = 'host' and g.target_id = $1)
    or (g.target_kind = 'group' and g.target_id in (
      select group_id from group_resources
      where resource_kind = 'host' and resource_id = $1
    ))
  );
