# Machine secrets

Deliver secrets to a *host* (not a human), for the app running on it to consume.
Reuses the SSH-access pipeline — signed push over the live daemon WS, reconcile on
connect — with two deliberate departures: the unit is a **set** (one app's `.env`),
and the opened values are **never written to disk**.

## The DX that must stay true

1. Dev has a local `.env`. Pastes it into custos → a **set** named `billing`.
2. It's bound to host `web01`.
3. One line in the systemd unit: `ExecStart=custosd exec --set billing -- node server.js`.
4. App reads `process.env.MASTER_KEY`. It knows nothing about custos — no library, no code.

## Model

The vault is otherwise human-only: `grants` key access to `user_id`, secrets are
revealed to a browser over HTTP. This adds the host as a first-class consumer:

1. Each host registers an X25519 **encryption** key at enroll (its Ed25519 identity only signs).
2. A **set** is a named map of `KEY→value` — one app's env. Sets are bound to hosts.
3. The control plane seals the whole bundle to the host's key and pushes it over the WS.
4. The daemon holds the opened bundle **in memory only** and serves it over a local socket.
5. `custosd exec --set <name> -- <app>` injects the values as env vars, then becomes the app.

## Data model

Machine sets are their own tables, separate from the human `secrets` table (which is a
password-manager item: `label, url, username`, sealed `{password, notes}`). They share the
vault sealing *code*, not a table.

```
secret_sets(id, name, created_by, …)            -- the delivery construct
secret_set_entries(set_id, key, ciphertext, …)  -- individually vault-sealed values, owned by a set
host_set_bindings(host_id, set_id, as_user, …)  -- deliver a set to a host; as_user opt-in scopes it
set_audit_logs(set_name, entry_key, host_id, action, actor, at)  -- append-only
hosts.encryption_key   -- host X25519 public key
hosts.last_set_seq     -- monotonic per-host counter for signed set pushes (separate from snapshot seq)
```

Entries are owned by one set (matches paste-an-`.env`). Sharing a value across sets is a later
addition (promote entries to standalone + a join), not a redesign.

## Access model (grant-based, not admin-only)

Sets use the same permission model as secrets — nothing is gated behind `requireAdmin`:

- `set.add` (global) to create · `set.read` (scoped) to view · `set.manage` (scoped) to edit/delete.
- Members see only their readable sets; admins bypass every check.
- **Creators own what they create:** `grantOwner` self-grants `set.read`+`set.manage` inside the
  create transaction (same for secrets and groups). Ownership is ordinary grants — auditable, revocable.
- **Binding needs authority over both ends:** `set.read` on the set **and** `host.access` on the host.
  You can only deliver a set to a host you're trusted on and allowed to read.

## Crypto & wire format

Three layers, each answering a different question:

| Layer | Algorithm | Question it answers |
|---|---|---|
| at rest | per-secret AES-256-GCM data key, wrapped by the master key | stored sealed in Postgres |
| confidentiality (e2e to host) | X25519 ECDH → HKDF-SHA256 → AES-256-GCM (`internal/hybrid`) | only this host can read it |
| authenticity + replay | **Ed25519** signature over the envelope | it's really the CP, and it's fresh |

**Why both seal and sign.** Sealing is to a *public* key, so it's anonymous — anyone who knows the
host's `ENC_pub` (a public value) could forge a valid, GCM-authenticated bundle and inject secrets the
app would trust. The Ed25519 signature (verified against the CP key pinned at enroll) is what proves CP
authorship; its covered `seq` blocks replay of a captured bundle. The daemon **verifies the signature
before it decrypts**.

The bundle is sealed **once, whole** — names and `as_user` live inside the ciphertext, so nothing leaks:

```
Envelope (JSON over the WS) { type: "secret_sets", seq, sig, data }

  sig  = Ed25519( "custos-sets:v1" ‖ len16(hostID) ‖ hostID ‖ seq(8B) ‖ data )
  data = { "sealed": <blob, base64> }
  blob = eph_pub(32) ‖ nonce(12) ‖ AES-256-GCM( JSON(SecretSets) ) ‖ tag(16)

  SecretSets = { sets: [ { name, as_user, version, values:{KEY:val,…} }, … ] }
```

One ephemeral key per push (generated inside `Seal`, its public half is the first 32 bytes of the blob).
`version` is the set's `updated_at` nanos, so the daemon can detect a changed set for reload later.

## Delivery

`buildSecretSets` resolves the host's bindings and decrypts each entry into the cleartext bundle;
`secretSetsEnvelope` seals it once to the host key, stamps `NextHostSetSeq`, and signs it. Pushed via
the hub on **connect**, on **bind/unbind**, and on **set edit/delete** (bound hosts captured before the
cascade delete). Daemon rejects `seq ≤ last`.

## Daemon: memory only

For SSH access the daemon keeps a last-known-good disk cache — access entries are public keys. Secrets
are the opposite: a secret on disk is useful forever, offline, silently. The host's private key on disk
is *not* equivalent — it's only useful *live*, against an authenticated, revocable, audited WS.

On `TypeSecretSets`: verify sig → seq check → `hybrid.Open` → store in an in-memory map, never the disk
cache. Consequences:

- **No offline fallback** — CP down + daemon restart = no secrets until reconnect.
- **Memory hardened** at startup (`run.go`, Linux, best-effort): `mlockall` (no swap),
  `PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0` (no core dumps). Without these, "in memory" leaks to disk.
- **TPM/PKCS#11 for the identity key** would close "disk image → impersonate host". Deferred.

## Consumption: `custosd exec`

The app needs zero custos code — the `doppler run --` / `aws-vault exec` pattern: a wrapper sets env,
then `execve`s the target, replacing itself in the same PID.

The **only** client of the secrets socket is `custosd exec` — apps never touch it. exec is a short-lived
process with none of the daemon's state (WS, key, opened bundle), so it asks the daemon over the socket:

1. Connect to `/run/custos/secrets.sock`, send the set name.
2. Daemon serves the values as JSON — for a scoped set, only if `SO_PEERCRED` says the caller's uid
   matches `as_user`.
3. exec sets the values as env vars and `execve`s the target.

Values live only in the child's env memory — never a file, never disk.

**Isolation without a bootstrap secret.** `custosd exec` runs as the app's (untrusted) service user
(systemd `User=billing-svc`). The daemon reads the caller's kernel-verified uid via `SO_PEERCRED` and,
for a scoped set, serves it only if that uid matches `as_user`. No token to issue or store — the kernel
vouches for identity. Unscoped sets (`as_user` null) are the single-tenant default: any group member may
read them.

**Fail closed and loud.** On any rejection — forbidden, timeout, daemon error — exec exits non-zero and
does **not** `execve`. The app never starts with half its env: it doesn't start, and the reason goes to
stderr → the journal (with the running user, for the wrong-user case), while systemd marks the unit
failed. The daemon logs denials host-side. exec retries the transient "not synced yet" case up to
`--timeout` (default 30s) so a CP outage at boot waits rather than crash-loops. Injection is atomic
(whole set or nothing).

**Audit.** A successful serve is reported to the CP over the WS (`TypeSecretRead`) and recorded in
`set_audit_logs` as a `machine_read` (host + set + time), viewable at `GET /sets/{id}/audit` alongside
`create`/`edit`/`deliver`/`delete`. Denials are logged host-side on the daemon.

## Install wiring

- The secrets socket lives in the systemd `RuntimeDirectory` (`/run/custos/secrets.sock`) — the only
  place the `custos`-user daemon can bind. `ExecStart` passes `--secret-socket`.
- The socket is `0660 custos:custos`. For an app to consume secrets, its service user joins the `custos`
  group (`usermod -aG custos <app-user>`) — surfaced in the install output. `SO_PEERCRED` + `as_user`
  scope within the group.

## Deferred (not blocking "it works")

- Live rotation without restart — a tmpfs file the daemon rewrites + the app watches, or the socket
  queried at runtime; both reuse the in-memory store.
- Signing the `upgrade` message.
- **TPM/PKCS#11-backed host keys** — generate the identity/encryption keys inside tamper-resistant
  hardware so they're non-extractable; a stolen disk image then can't impersonate the host or open a
  captured bundle. Platform-specific (and TPM 2.0's Curve25519 support is limited, so likely P-256).
