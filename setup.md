# Setup

Two binaries: `custos` (control plane, `cmd/api`) and `custosd` (per-host daemon, `cmd/daemon`).

## Control plane

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

## Enroll a host

6. Via the API (as admin): **log in**, then **create an enrollment token** (`POST /enroll-tokens`,
   with the host's managed unix accounts).
7. On the host, as root: **`sudo custosd install`** — creates the `custos` user, installs the binary to
   `/usr/local/bin`, writes the systemd unit, and wires sshd (`AuthorizedKeysCommand`).
8. **Enroll** as the custos user:
   `sudo -u custos custosd enroll --control-plane $URL --token $TOKEN --dir /var/lib/custos`
   (generates the host's Ed25519 identity + X25519 encryption keys, registers their public halves).
9. **Start:** `sudo systemctl enable --now custosd`.

## Grant SSH access

10. Via the API: **register the admin's SSH public key** (`POST /keys`), then **grant** them
    `host.access` on the host (`POST /grants`).
11. `ssh` into the host — the login is gated by custos via the daemon.

## Machine secrets (optional)

To deliver app secrets to the host instead of (or besides) SSH access, see
[machine-secrets.md](architecture/machine-secrets.md): create a set, bind it to the host, and launch
the app with `custosd exec --set <name> -- <command>`.

---

Dev shortcut: skip `install`/systemd and run the daemon directly with `custosd run --dir <dir>
--socket <path> --secret-socket <path>`; set `CUSTOS_ENCRYPTION=off` to talk to the API in plaintext.
