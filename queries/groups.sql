-- name: CreateGroup :one
insert into resource_groups (name, description) values ($1, $2) returning *;

-- name: ListGroups :many
select id, name, description, created_at from resource_groups order by name;

-- name: GetGroup :one
select * from resource_groups where id = $1;

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
select resource_kind, resource_id, added_at
from group_resources where group_id = $1 order by added_at;
