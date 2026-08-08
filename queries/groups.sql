-- name: CreateGroup :one
insert into resource_groups (name, description) values ($1, $2) returning *;

-- name: ListGroups :many
select id, name, description, created_at from resource_groups order by name;

-- name: ListReadableGroups :many
select distinct rg.id, rg.name, rg.description, rg.created_at
from resource_groups rg
join grants g on g.permission = 'group.read' and g.revoked_at is null
  and g.target_kind = 'group' and g.target_id = rg.id
where g.user_id = $1
order by rg.name;

-- name: ListGroupsForResource :many
select rg.id, rg.name, rg.description, rg.created_at
from group_resources gr
join resource_groups rg on rg.id = gr.group_id
where gr.resource_kind = $1 and gr.resource_id = $2
order by rg.name;

-- name: ListReadableGroupsForResource :many
select distinct rg.id, rg.name, rg.description, rg.created_at
from group_resources gr
join resource_groups rg on rg.id = gr.group_id
join grants g on g.permission = 'group.read' and g.revoked_at is null
  and g.target_kind = 'group' and g.target_id = rg.id
where g.user_id = $1
  and gr.resource_kind = $2
  and gr.resource_id = $3
order by rg.name;

-- name: ListGroupMembers :many
select u.id as user_id, u.email, u.name, u.display_name, u.role, u.status,
       g.id as grant_id, g.permission, g.created_at as granted_at
from grants g
join users u on u.id = g.user_id
where g.target_kind = 'group'
  and g.target_id = $1
  and g.revoked_at is null
order by u.email, g.permission;

-- name: GetGroup :one
select * from resource_groups where id = $1;

-- name: UpdateGroup :one
update resource_groups
set name = $2, description = $3
where id = $1
returning *;

-- name: DeleteGroup :execrows
delete from resource_groups where id = $1;

-- name: RevokeGroupGrants :exec
update grants set revoked_at = now()
where target_kind = 'group' and target_id = $1 and revoked_at is null;

-- name: AddGroupResource :exec
insert into group_resources (group_id, resource_kind, resource_id)
values ($1, $2, $3)
on conflict do nothing;

-- name: RemoveGroupResource :execrows
delete from group_resources
where group_id = $1 and resource_kind = $2 and resource_id = $3;

-- name: ListGroupResources :many
select gr.resource_kind, gr.resource_id, gr.added_at,
       h.id as host_id, coalesce(h.name, '') as host_name, coalesce(h.hostname, '') as host_hostname,
       coalesce(h.accounts, '{}'::text[]) as host_accounts, coalesce(h.status, '') as host_status,
       coalesce(h.agent_version, '') as host_agent_version, coalesce(h.desired_version, '') as host_desired_version,
       h.enrolled_at as host_enrolled_at, h.last_seen_at as host_last_seen_at,
       s.id as secret_id, coalesce(s.label, '') as secret_label, s.url as secret_url,
       s.username as secret_username, s.otp_recipient as secret_otp_recipient,
       s.created_at as secret_created_at, s.updated_at as secret_updated_at,
       ss.id as set_id, coalesce(ss.name, '') as set_name, ss.created_at as set_created_at,
       ss.updated_at as set_updated_at, coalesce(k.key_count, 0)::bigint as set_key_count
from group_resources gr
left join hosts h on gr.resource_kind = 'host' and h.id = gr.resource_id
left join secrets s on gr.resource_kind = 'secret' and s.id = gr.resource_id
left join secret_sets ss on gr.resource_kind = 'set' and ss.id = gr.resource_id
left join (
  select set_id, count(*) as key_count
  from secret_set_entries
  group by set_id
) k on k.set_id = ss.id
where gr.group_id = $1
order by gr.added_at;
