-- +goose Up
-- custos control-plane schema. UUID PKs, timestamptz throughout.

create extension if not exists pgcrypto; -- gen_random_uuid()

-- ── Identity & auth ─────────────────────────────────────────────────────────

create table users (
  id           uuid primary key default gen_random_uuid(),
  email        text not null unique,
  name         text not null,
  display_name text,                          -- optional nickname / preferred name
  role         text not null default 'member' check (role in ('admin', 'member')),
  status     text not null default 'active'  check (status in ('active', 'suspended', 'removed')),
  created_at timestamptz not null default now()
);

-- Login methods, one user -> many. failed_logins/locked_until throttle brute force.
create table identities (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references users(id) on delete cascade,
  provider       text not null,          -- 'password' | 'google' | 'slack' | ...
  external_id    text not null,          -- email for password; provider subject for oauth
  password_hash  text,                   -- argon2id; only for provider='password'
  created_at     timestamptz not null default now(),
  last_login_at  timestamptz,
  failed_logins  integer not null default 0,
  last_failed_at timestamptz,
  locked_until   timestamptz,
  unique (provider, external_id)
);
create index on identities (user_id);

create table invitations (
  id          uuid primary key default gen_random_uuid(),
  email       text not null,
  role        text not null default 'member' check (role in ('admin', 'member')),
  token_hash  text not null,
  invited_by  uuid references users(id),
  expires_at  timestamptz not null,
  accepted_at timestamptz,
  created_at  timestamptz not null default now()
);

-- A login session = the refresh token, plus the client's hybrid session pubkey.
create table sessions (
  id                uuid primary key default gen_random_uuid(),
  user_id           uuid not null references users(id) on delete cascade,
  token_hash        text not null unique, -- the refresh token
  client_public_key bytea,                -- X25519; null when API encryption is off (dev)
  created_at        timestamptz not null default now(),
  expires_at        timestamptz not null,
  revoked_at        timestamptz
);
create index on sessions (user_id);

-- Short-lived access tokens; a session mints many. Revoking the session cascades them.
create table access_tokens (
  id         uuid primary key default gen_random_uuid(),
  session_id uuid not null references sessions(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index on access_tokens (session_id);

create table password_resets (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  used_at    timestamptz,
  created_at timestamptz not null default now()
);

-- ── SSH access ──────────────────────────────────────────────────────────────

-- A user's registered SSH keys. Fingerprint unique system-wide: a key = one person.
create table public_keys (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references users(id) on delete cascade,
  label       text not null,
  key_type    text not null,
  key_blob    text not null,
  fingerprint text not null unique,
  created_at  timestamptz not null default now()
);
create index on public_keys (user_id);

-- A managed machine running custosd.
create table hosts (
  id           uuid primary key default gen_random_uuid(),
  name         text not null,
  hostname     text not null,
  identity_key text not null unique,          -- daemon's ed25519 public key, from enrollment
  accounts     text[] not null default '{}',  -- unix accounts custos manages on this host
  status       text not null default 'active' check (status in ('active', 'revoked')),
  enrolled_at  timestamptz not null default now(),
  last_seen_at timestamptz
);

-- Single-use enrollment tokens an admin generates for a new daemon.
create table enrollment_tokens (
  id         uuid primary key default gen_random_uuid(),
  token_hash text not null unique,
  label      text,
  accounts   text[] not null default '{}',    -- copied to hosts.accounts on enrollment
  created_by uuid references users(id),
  expires_at timestamptz not null,
  used_at    timestamptz,
  host_id    uuid references hosts(id),
  created_at timestamptz not null default now()
);

-- ── Resources, groups & permissions ─────────────────────────────────────────

-- A credential item: plaintext metadata plus a sealed JSON blob of the secret
-- fields ({password?, notes?}). The blob columns are null when there are none.
create table secrets (
  id            uuid primary key default gen_random_uuid(),
  label         text not null,
  url           text,
  username      text,
  otp_recipient text,                          -- phone / email / name; metadata
  ciphertext    bytea,                         -- vault-sealed JSON of secret fields
  nonce         bytea,
  wrapped_key   bytea,
  created_by    uuid references users(id),
  updated_by    uuid references users(id),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table resource_groups (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  description text not null default '',
  created_at  timestamptz not null default now()
);

-- Group membership. Polymorphic: a secret or host can be bucketed into groups.
create table group_resources (
  group_id      uuid not null references resource_groups(id) on delete cascade,
  resource_kind text not null check (resource_kind in ('secret', 'host')),
  resource_id   uuid not null,
  added_at      timestamptz not null default now(),
  primary key (group_id, resource_kind, resource_id)
);

create table permissions (
  key         text primary key,
  description text not null
);

-- A user granted a permission, globally or on one resource. Group targets cascade
-- to members at resolve time. Soft-revoked to keep the trail.
create table grants (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references users(id) on delete cascade,
  permission  text not null references permissions(key),
  target_kind text not null check (target_kind in ('secret', 'host', 'group', 'global')),
  target_id   uuid,                            -- null iff global
  granted_by  uuid references users(id),
  created_at  timestamptz not null default now(),
  revoked_at  timestamptz,
  check ((target_kind = 'global') = (target_id is null))
);
create index on grants (user_id) where revoked_at is null;
create index on grants (target_kind, target_id) where revoked_at is null;

-- ── Audit ───────────────────────────────────────────────────────────────────

-- secret_id is nulled (not cascaded) on delete and the name is denormalized, so a
-- delete entry survives the secret it records.
create table secret_audit_logs (
  id          uuid primary key default gen_random_uuid(),
  secret_id   uuid references secrets(id) on delete set null,
  secret_name text not null,
  action      text not null check (action in ('read', 'add', 'update', 'delete')),
  user_id     uuid references users(id) on delete set null,
  at          timestamptz not null default now()
);
create index on secret_audit_logs (secret_id, at);

-- SSH login attempts. fingerprint is denormalized and public_key_id nulls on
-- delete, so history survives a removed key.
create table ssh_access_logs (
  id            uuid primary key default gen_random_uuid(),
  host_id       uuid not null references hosts(id) on delete cascade,
  public_key_id uuid references public_keys(id) on delete set null,
  account       text not null,
  allowed       boolean not null,
  at            timestamptz not null,
  fingerprint   text not null default ''
);
create index on ssh_access_logs (host_id, at);

-- ── Seed data ───────────────────────────────────────────────────────────────

insert into permissions (key, description) values
  ('secret.add',    'Create secrets'),                              -- global
  ('group.create',  'Create resource groups'),                     -- global
  ('secret.read',   'View a secret value'),                        -- scoped
  ('secret.update', 'Modify secrets'),                             -- scoped
  ('secret.delete', 'Delete secrets'),                             -- scoped
  ('host.access',   'SSH access to a host'),                       -- scoped
  ('group.manage',  'Rename, delete, or change membership of a group'); -- scoped

-- +goose Down
drop table if exists ssh_access_logs cascade;
drop table if exists secret_audit_logs cascade;
drop table if exists grants cascade;
drop table if exists permissions cascade;
drop table if exists group_resources cascade;
drop table if exists resource_groups cascade;
drop table if exists secrets cascade;
drop table if exists enrollment_tokens cascade;
drop table if exists hosts cascade;
drop table if exists public_keys cascade;
drop table if exists password_resets cascade;
drop table if exists access_tokens cascade;
drop table if exists sessions cascade;
drop table if exists invitations cascade;
drop table if exists identities cascade;
drop table if exists users cascade;
drop extension if exists pgcrypto;
