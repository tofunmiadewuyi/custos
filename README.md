# custos

Centralized SSH access **and** secrets for a fleet of machines.

Custos replaces hand-managed `authorized_keys` files and `.env` secrets scattered across
servers with one control plane. Grant a teammate SSH access to a host — or revoke it — from a
single place, and it takes effect on the next login. Store an app's secrets once and have them
delivered, sealed, to the hosts that run it. Every access and every secret read is audited.

## How it works

Two binaries:

- **`custos`** — the control plane: an HTTP API backed by Postgres. Source of truth for users,
  hosts, keys, grants, and secrets.
- **`custosd`** — a per-host daemon. It hooks sshd's `AuthorizedKeysCommand` so every SSH login is
  gated by custos, and it holds a long-lived WebSocket to the control plane (dialing *out*, so hosts
  need no inbound ports). It receives authorized-key snapshots and sealed secret sets, and serves
  those secrets to local apps.

Access is **grant-based**: admins grant, members exercise. SSH keys are pushed to hosts as signed
snapshots; secret sets are sealed end-to-end to each host's key (the daemon holds them in memory
only, never on disk). See [`architecture/`](architecture/) for the protocol and machine-secrets
design.

## Setup

### Control plane

1. **Generate keys:** `custos gen-keys` — prints `CUSTOS_MASTER_KEY`, `CUSTOS_SIGNING_PRIVATE_KEY`,
   `CUSTOS_CLIENT_PRIVATE_KEY` (+ `CUSTOS_CLIENT_PUBLIC_KEY` to embed in the frontend).
2. **Set env** for the API server:
   - Provide: `CUSTOS_DATABASE_URL`, `CUSTOS_LISTEN_ADDR`.
   - From gen-keys: `CUSTOS_MASTER_KEY`, `CUSTOS_SIGNING_PRIVATE_KEY`, `CUSTOS_CLIENT_PRIVATE_KEY`.
   - Optional: `CUSTOS_ENCRYPTION` (default on; off in dev), `CUSTOS_CORS_ORIGINS`, email
     (`RESEND_API_KEY`, `CUSTOS_EMAIL_FROM`, `CUSTOS_APP_URL`).
3. **Migrate:** `custos migrate up` — creates the schema (required before create-admin).
4. **Seed admin:** `custos create-admin` — creates the first admin; prints a generated password.
5. **Run:** `custos serve`.

### Enroll a host

6. Via the API (as admin): **log in**, then **create an enrollment token** (`POST /enroll-tokens`,
   with the host's managed unix accounts).
7. On the host, as root: **`sudo custosd install`** — creates the `custos` user, installs the binary to
   `/usr/local/bin`, writes the systemd unit, and wires sshd (`AuthorizedKeysCommand`).
8. **Enroll** as the custos user:
   `sudo -u custos custosd enroll --control-plane $URL --token $TOKEN --dir /var/lib/custos`
   (generates the host's Ed25519 identity + X25519 encryption keys, registers their public halves).
9. **Start:** `sudo systemctl enable --now custosd`.

### Grant SSH access

10. Via the API: **register the admin's SSH public key** (`POST /keys`), then **grant** them
    `host.access` on the host (`POST /grants`).
11. `ssh` into the host — the login is gated by custos via the daemon.

### Machine secrets (optional)

To deliver app secrets to the host instead of (or besides) SSH access, see
[machine-secrets.md](architecture/machine-secrets.md): create a set, bind it to the host, and launch
the app with `custosd exec --set <name> -- <command>`.

---

Dev shortcut: skip `install`/systemd and run the daemon directly with `custosd run --dir <dir>
--socket <path> --secret-socket <path>`; set `CUSTOS_ENCRYPTION=off` to talk to the API in plaintext.

## Development

```bash
make test              # unit tests (no database, fast)
make test-race         # unit tests with the race detector
make test-integration  # hermetic: spins ephemeral Postgres in Docker (needs a Docker daemon)
make build-api         # -> bin/api
make build-daemon      # -> bin/daemon
```
