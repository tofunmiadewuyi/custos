# Daemon update path

How an enrolled `custosd` fleet upgrades. Distribution (GitHub release tarballs +
`install.sh`) handles first install; this is the upgrade of already-running hosts.

Controlled push: an admin targets one host or the whole fleet with a version. The control
plane pushes it over the existing authenticated daemon websocket; the daemon downloads,
verifies, and swaps its own binary via a root systemd step. Idempotent at every layer — a
host already on the target is a no-op.

## Flow

1. **Trigger.** `POST /hosts/{id}/upgrade` or `POST /upgrade` (admin, `{"version":"vX.Y.Z"}`).
   The control plane resolves the release's per-arch digests from `..._checksums.txt`
   (`resolveChecksums`), records `hosts.desired_version`, and pushes `TypeUpgrade{Version,
   SHA256: arch→digest}` to online hosts. Offline hosts get it on reconnect.
2. **Stage** (daemon, unprivileged). `client.handleUpgrade` → `stageUpgrade`: download the
   arch tarball, verify against the pushed digest, extract `custosd`, atomic-rename it to
   `/var/lib/custos/update/custosd.staged` (+ `staged.json`), then exit so systemd restarts.
3. **Apply** (root). The unit has `ExecStartPre=+custosd apply-update`. The `+` runs it as
   root though the service is `User=custos`. It re-verifies the staged binary's digest,
   smoke-tests `custosd version`, backs up `/usr/local/bin/custosd` → `.prev`, atomically
   swaps in the new binary, and clears the staged files. `ExecStart` then runs the new build.
4. **Converge.** The daemon reports `Version` in its `Auth` on reconnect → `hosts.agent_version`.

## Trust

The digest comes from the control plane over the authenticated link, so it — not the
release host — is the trust anchor. Deferred hardening: an Ed25519 signature over each
release, pinned into the daemon (grows `Upgrade` a `Sig` field without a redesign).

## Key files

- `internal/protocol`: `TypeUpgrade`, `Upgrade`, `Auth.Version`.
- `internal/daemon`: `update.go` (stage), `client.go` (`handleUpgrade`, `ErrRestart`).
- `cmd/daemon`: `applyupdate.go` (root swap), `install.go` (`ExecStartPre` + `update/` dir).
- `internal/controlplane`: `upgrades.go` (endpoints + checksum resolver), `daemon_ws.go`
  (persist version, reconnect push), `hub.online`.
