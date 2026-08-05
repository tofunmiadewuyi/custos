-- +goose Up

alter table set_audit_logs
  add column if not exists set_id uuid;

create index if not exists set_audit_logs_set_id_at_idx
  on set_audit_logs (set_id, at);

alter table set_audit_logs
  drop constraint if exists set_audit_logs_action_check;

alter table set_audit_logs
  add constraint set_audit_logs_action_check
  check (action in ('create', 'edit', 'rename', 'deliver', 'machine_read', 'delete'));

-- +goose Down

alter table set_audit_logs
  drop constraint if exists set_audit_logs_action_check;

alter table set_audit_logs
  add constraint set_audit_logs_action_check
  check (action in ('create', 'edit', 'deliver', 'machine_read', 'delete'));

drop index if exists set_audit_logs_set_id_at_idx;

alter table set_audit_logs
  drop column if exists set_id;
