# Machine secrets

Deliver secrets to a *host* (not a human), for the app running on it to consume. Reuses the
SSH-access pipeline — signed push over the live daemon WS, reconcile on connect — with two
deliberate departures: the unit is a **set** (one app's `.env`), and values are **never
written to disk.**

## The DX that must stay true

The whole thing is worthless if apps can't get secrets ergonomically. The headline flow,
which every design choice below protects:

1. Dev has a local `.env`. Pastes it into custos → a **set** named `billing`.
2. Admin binds it: `billing` → host `web01`.
3. One line in the systemd unit: `ExecStart=custosd exec --set billing -- node server.js`.
4. App reads `process.env.MASTER_KEY`. It knows nothing about custos — no library, no code.

No per-secret ceremony, no UIDs, no name collisions. That bar is the point of the set model.

## Model

Today the vault is human-only: `grants` are keyed to `user_id`, secrets are revealed to a
browser over HTTP. This adds the host as a first-class consumer:

1. Each host gets an X25519 **encryption** key at enroll (its Ed25519 identity only signs).
2. A **set** is a named map of `KEY→value` — one app's env. Admin binds sets to hosts.
3. Control plane seals each bound set to the host's key and pushes it over the WS.
4. The daemon holds decrypted sets **in memory only** and dispenses them over a local socket.
5. `custosd exec --set <name> -- <app>` injects the set as env vars, then becomes the app.

## Why the unit is a *set*, not a named secret

A flat namespace of named secrets per host is the wrong model, and collisions are the symptom:
two apps both want `MASTER_KEY`; a flat socket hands any caller everything. Both problems vanish
when the unit of storage, delivery, and consumption is a **set of key→value pairs** — one app's
`.env`. Sets don't share a namespace: `billing`'s `MASTER_KEY` and `payments`'s `MASTER_KEY`
never meet and can't collide. The only uniqueness rules are the natural `.env` ones: keys unique
*within* a set, set names unique per org. No `APP_NAME_` prefixing — you were never meant to be
in a shared namespace. This is the Doppler project/config and Kubernetes-Secret shape.

### Sets are a different shape from the human vault — a separate concept

**Two separate worlds that share the sealing *code*, not a table.** `secrets` stays exactly as
it is — the human password-manager (`label, url, username, otp_recipient` + sealed
`{password, notes}`), read one at a time in a UI. A machine env var is just `KEY = value`;
forcing it into the human shape (one heavyweight row per var, human columns null) is what makes
the model muddy. So no rename, no reuse: an env entry *is* the machine secret — individually
sealed, individually auditable — and a **set** owns its entries. Both call `vault.Seal/Open`, so
there's no duplicated crypto, just no shared table.

```sql
-- the named delivery/access construct (one app's .env)
create table secret_sets (
  id         uuid primary key default gen_random_uuid(),
  name       text not null unique,           -- org-scoped, human-referenced
  created_by uuid references users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- the individual machine secrets: key + sealed value, owned by a set.
create table secret_set_entries (
  set_id      uuid not null references secret_sets(id) on delete cascade,
  key         text not null,                 -- env var name, e.g. MASTER_KEY
  ciphertext  bytea not null,                -- vault-sealed value (same Seal/Open as the human vault)
  nonce       bytea not null,
  wrapped_key bytea not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  primary key (set_id, key)                  -- keys unique within a set, like a .env line
);

-- deliver a set to a host; optional service-account isolation.
create table host_set_bindings (
  host_id    uuid not null references hosts(id) on delete cascade,
  set_id     uuid not null references secret_sets(id) on delete cascade,
  as_user    text,                           -- opt-in unix account; null = single-tenant
  granted_by uuid references users(id),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  primary key (host_id, set_id)
);

-- machine reads/deliveries, parallel to secret_audit_logs
create table set_audit_logs (
  id        uuid primary key default gen_random_uuid(),
  set_name  text not null,                   -- denormalized, survives deletion
  entry_key text,                            -- null for whole-set actions
  host_id   uuid,                            -- who consumed it
  action    text not null,                   -- create | edit | deliver | machine_read | delete
  actor     uuid references users(id),       -- null for machine-initiated
  at        timestamptz not null default now()
);
```

Entries are **owned by one set**, not shared across sets — matches paste-an-`.env` exactly. If a
value is ever needed in two sets, promote entries to standalone + a join table later; no redesign.

## Crypto flow

Ed25519 signs, it can't receive encrypted data, so hosts get a second key. `internal/hybrid`
already does X25519 seal/open (the frontend uses it). Per bound set:

1. Control plane unwraps each entry's data key with the master key, AES-GCM-decrypts → plaintext
   (transient, in CP memory — inherent to the existing non-zero-knowledge design; no new trust).
2. `hybrid.Seal` the assembled set map to the host's registered X25519 public key.
3. Push; daemon `hybrid.Open`s with its X25519 private key.

Sealed to the host end-to-end — we do **not** rely on the transport for confidentiality. WS is
wss on top of that.

## Delivery (clone of the snapshot path)

New envelope type, signed like snapshots (own domain-sep tag), own seq counter so it never
interferes with SSH-snapshot anti-replay:

```go
TypeSecretSets MessageType = "secret_sets" // control plane -> daemon

type SealedSet struct {
    Name    string `json:"name"`
    AsUser  string `json:"as_user,omitempty"` // enforced by the daemon socket, if set
    Version uint64 `json:"version"`           // bumps on any entry change; drives reload
    Sealed  []byte `json:"sealed"`            // hybrid-sealed JSON map {KEY: value}
}

type SecretSets struct {
    Sets []SealedSet `json:"sets"`
}
```

Control plane `secretSetsFor(hostID)`: resolve `host_set_bindings` → for each set, decrypt entries
+ seal the map to the host key → assemble. Push via the hub on **connect**, on **bind/unbind**, and
on **set edit** (extending the fan-out that already re-pushes SSH snapshots on grant change). Carries
`seq` from a new `hosts.last_set_seq`; daemon rejects `seq <= last`.

## Daemon: memory only (the deliberate divergence)

For SSH access the daemon keeps a last-known-good **disk** cache — access entries are public keys,
and not locking people out during a CP outage is worth it. Secrets are the opposite: a secret on
disk is useful forever, offline, silently (backups, swap, a stolen SSD). The host's private key on
disk is *not* equivalent — it's only useful *live*, against an authenticated, rate-limited,
revocable, audited WS. That asymmetry is the whole design.

On `TypeSecretSets`: verify sig → `hybrid.Open` → store in an **in-memory map**, never the `Cache`.
Consequences accepted:

- **No offline fallback.** CP down + daemon restart = no secrets until reconnect (unlike SSH).
- **Memory hardening required** or "in memory" is a fiction: `mlockall` (no swap),
  `PR_SET_DUMPABLE=0` (no core dumps) at startup in `run.go`.
- **TPM/PKCS#11 for the identity key** is the eventual close on "disk image → impersonate host."
  Out of scope; noted so enrollment can grow hardware-backed keys without a redesign.

## Consumption: `custosd exec`

The app needs **zero** custos code — the standard machine-secrets pattern (`doppler run --`,
`aws-vault exec`, `chamber exec`): a wrapper sets env, then `execve`s the target, replacing itself
in the same PID. The app reads its env and never knows custos exists.

`exec` is a short-lived client of the **daemon's local socket** (the mechanism `authkeys` already
uses, `authserver.go`) — it does not hold the daemon's memory and never re-auths to the CP itself:

1. Connect to `/run/custos/custosd.sock`, request set `billing`.
2. Set every `KEY→value` in the set as an env var.
3. `execve` the target command.

The values live only in the child's env memory. Never a file, never the disk.

### Isolation: unspoofable identity, no bootstrap secret

The socket is a secret oracle — a caller reads whatever it's served. Rather than issue per-app
tokens (which reintroduce a bootstrap secret — where does *that* live?), the daemon reads the
caller's kernel-verified UID via `SO_PEERCRED`. The kernel vouches for who the caller is, for free.

- **Single-tenant host (default):** set `as_user` is null; whoever writes the systemd unit picks
  `--set X`. If someone can edit your units, they own the box — UID enforcement buys nothing.
- **Multi-tenant / mutually untrusted (opt-in):** bind with `as_user: billing-svc` — the service
  account the app's unit *already* runs as. The daemon resolves that name → UID locally and serves
  the set only to a caller whose peer-cred UID matches. `payments-svc` asking for `billing` is
  denied by kernel-vouched identity, no token in play.

The human never types a UID — `as_user` is a name you already use; the number is resolved on the host.

### App-down behavior

If the daemon has no sets yet (CP down since boot), the socket returns "unavailable." `exec` blocks
up to `--timeout` (default 30s) for first sync, then fails non-zero — the app waits at boot rather
than crash-looping; systemd restarts on failure.

### Rotation

env is frozen at process start, so exec/env = **restart to pick up an edited set**. Fine for the
classic case (read once at boot). Live rotation without restart is a later addition — a file on
tmpfs (`/run`, RAM-backed) the daemon rewrites and the app watches, or the socket queried at runtime.
Both reuse the same in-memory store and the same peer-cred isolation; neither needs a library.

## Creation & audit

Creation maps straight onto the schema, one tx — the UI splits the pasted `.env` into `entries`:

```
POST /sets  { name, entries: [{ key, value }] }
```
→ insert the `secret_sets` row, `vault.Seal` each value, insert N `secret_set_entries`.

`secret_audit_logs` stays human-only. Machine activity lands in its own `set_audit_logs` (above):
`create | edit | deliver | machine_read | delete`, with `host_id` for consumption and `entry_key`
for per-value edits. Every push and every socket read is logged, so a machine read is as traceable
as a human reveal.

## Decisions (defaulted; override if wanted)

1. **Set seq**: separate `hosts.last_set_seq`, not shared with SSH-snapshot `last_seq`.
2. **Consumption first**: `custosd exec` over the local socket. File-on-tmpfs + socket-at-runtime
   are follow-ups for live rotation.
3. **Isolation default**: `as_user` null (single-tenant); peer-cred enforcement is opt-in per bind.
4. **App-down**: `exec` blocks up to `--timeout` (30s) for first sync, then fails non-zero.

## Concrete change list

**Shared**
- `internal/protocol`: `TypeSecretSets`, `SealedSet`, `SecretSets`; new signing tag + input for
  sets; `EncryptionKey` field on `EnrollRequest`.

**Daemon**
- `internal/daemon/enroll.go` + `store.go`: generate + persist an X25519 keypair at enroll, send
  the public half.
- `internal/daemon/client.go`: handle `TypeSecretSets` in `dispatch` → verify + open + store in a
  new in-memory sets map (not `Cache`).
- `internal/daemon/authserver.go`: serve set lookups on the local socket; enforce `SO_PEERCRED`
  against `as_user` when set.
- `cmd/daemon/run.go`: `mlockall` + disable core dumps at startup.
- `cmd/daemon/main.go` + new `cmd/daemon/exec.go`: `custosd exec --set NAME [--timeout d] -- cmd...`
  (socket client → env → execve).
- `cmd/daemon/install.go`: ensure socket perms gate the oracle.

**Control plane**
- Migration: `secret_sets`, `secret_set_entries`, `host_set_bindings`, `set_audit_logs`;
  `hosts.encryption_key text`; `hosts.last_set_seq bigint`.
- `queries/`: set CRUD, entry upsert (paste-`.env` = bulk), bind/unbind, `SetsForHost`,
  `SetHostEncryptionKey`, `BumpHostSetSeq`; `sqlc generate`.
- `internal/controlplane/enroll.go`: persist `EncryptionKey`.
- New `internal/controlplane/secret_sets.go`: set CRUD (`POST /sets` bulk-creates entries) +
  `POST /hosts/{id}/sets`, `DELETE /hosts/{id}/sets/{setId}` (admin), wired in `server.go`.
- `internal/controlplane/hub.go` + `daemon_ws.go`: `secretSetsFor` + push on connect, bind/unbind,
  set edit; sign with the sets tag.
```
