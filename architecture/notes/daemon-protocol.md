# Daemon ↔ control-plane protocol

The daemon holds one long-lived **WebSocket** to the control plane (it dials out; hosts need no
inbound ports). Every message is a JSON **`Envelope`**; the payload and its security properties
depend on the `Type`.

```go
type Envelope struct {
    Type MessageType     // which message; selects how Data is read
    Data json.RawMessage // the payload, always the JSON of that type's struct
    Seq  uint64          // monotonic per-host; anti-replay on signed types
    Sig  []byte          // Ed25519 signature, present on signed types
}
```

## Two trust layers

1. **WSS / TLS** — protects *every* message hop-by-hop and authenticates the *server*. May terminate
   at a proxy in front of the control plane.
2. **App-level sign / seal** — end-to-end **CP ↔ host**, survives that proxy. Only some messages carry
   it, by need (below).

So app-level crypto exists exactly where an end-to-end guarantee is required: `snapshot`/`secret_sets`
are **signed** so authenticity + `seq` hold even past a TLS-terminating proxy; `secret_sets` is also
**sealed** so the secrets stay confidential end-to-end (a proxy sees only the blob).

## Message table

| Message | Dir | Encrypted | Signed | What secures it |
|---|---|---|---|---|
| `ping` / `pong` | both | no | no | nothing — keepalive |
| `challenge` | CP → d | no | no | a random nonce; nothing to forge |
| `auth` | d → CP | no | **signed by the daemon** (host identity) | host proves who it is |
| `snapshot` | CP → d | no | **signed by CP** | authenticity + replay (public keys, no need to hide) |
| `upgrade` | CP → d | no | no | WSS + the sha256 digest in the payload anchors the download |
| `secret_sets` | CP → d | **yes** (to host X25519) | **signed by CP** | confidential *and* authentic end-to-end |
| `access_log` | d → CP | no | no | the authenticated session |
| `secret_read` | d → CP | no | no | the authenticated session |

`grant` / `revoke` types exist in the protocol but aren't in the live path — bulk revoke re-sends a
full `snapshot`.

## The handshake (challenge / auth)

Authenticates the *host* to the CP (the CP is trusted via TLS — the daemon dialed a known URL):

- CP → daemon: `challenge` = `{ nonce }` (unsigned).
- daemon → CP: `auth` = `{ host_id, signature, version }` — the daemon signs the nonce with its
  **host identity Ed25519 key** under the `custos-host-auth:v1:` domain prefix. The CP verifies against
  the identity public key registered at enroll.

## Keys

Three keypairs, registered (public halves) at enroll:

| Keypair | Alg | Private held by | Public held by | Used for |
|---|---|---|---|---|
| host identity | Ed25519 | daemon | CP (`hosts.identity_key`) | daemon signs the `challenge` nonce in `auth` |
| CP signing | Ed25519 | CP | daemon (`SigningPublicKey`) | CP signs `snapshot` and `secret_sets` |
| host encryption | X25519 | daemon (`encryption.key`) | CP (`hosts.encryption_key`) | CP seals `secret_sets` to the host; daemon opens |

## Signing input & sequence

Signed messages sign `tag ‖ len16(hostID) ‖ hostID ‖ seq(8B) ‖ Data`, each type under its own
domain-separation tag so a signature for one can't be replayed as another:

- `snapshot` → `custos-snapshot:v1`, sequenced by `hosts.last_seq`.
- `secret_sets` → `custos-sets:v1`, sequenced by `hosts.last_set_seq` (separate counter).

The daemon **verifies the signature before it decrypts**, and drops any `seq ≤` the last it applied.

## `secret_sets` wire shape

The whole bundle is sealed **once** — set names and `as_user` live inside the ciphertext, so nothing
leaks:

```
Envelope { type: "secret_sets", seq, sig, data }

  sig  = Ed25519( "custos-sets:v1" ‖ len16(hostID) ‖ hostID ‖ seq(8B) ‖ data )
  data = { "sealed": <blob, base64> }
  blob = eph_pub(32) ‖ nonce(12) ‖ AES-256-GCM( JSON(SecretSets) ) ‖ tag(16)

  SecretSets = { sets: [ { name, as_user, version, values:{KEY:val,…} }, … ] }
```

The seal is X25519 ECDH (ephemeral CP key × host `ENC_pub`) → HKDF-SHA256 → AES-256-GCM. One ephemeral
key per push; its public half is the first 32 bytes of the blob. The GCM tag proves integrity but not
*sender* — anyone with the host's public key could forge a valid-looking sealed blob — which is why the
Ed25519 signature (authenticity) and `seq` (replay) are also required. Verify-sig-then-decrypt.
