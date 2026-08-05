-- +goose Up

alter table group_resources
  drop constraint if exists group_resources_resource_kind_check;

alter table group_resources
  add constraint group_resources_resource_kind_check
  check (resource_kind in ('secret', 'host', 'set'));

-- +goose Down

delete from group_resources where resource_kind = 'set';

alter table group_resources
  drop constraint if exists group_resources_resource_kind_check;

alter table group_resources
  add constraint group_resources_resource_kind_check
  check (resource_kind in ('secret', 'host'));
