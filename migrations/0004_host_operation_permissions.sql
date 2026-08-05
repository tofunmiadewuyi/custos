-- +goose Up

insert into permissions (key, description) values
  ('host.revoke',  'Revoke/decommission a host'),
  ('host.upgrade', 'Upgrade a host agent'),
  ('host.audit',   'View host access audit')
on conflict (key) do nothing;

-- +goose Down

delete from permissions
where key in ('host.revoke', 'host.upgrade', 'host.audit');
