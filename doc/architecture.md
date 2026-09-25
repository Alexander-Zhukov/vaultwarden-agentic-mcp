# Architecture

```
MCP client ──bearer──> /mcp ──> mcpserver ──> vault ──> keys
program ─────────────> /v1/links, /v1/upload ─┘   └───> bitwarden ──> Vaultwarden
```

| Package | Responsibility |
|---|---|
| `keys` | master key (PBKDF2, Argon2id), EncString and attachment buffers, RSA-OAEP key wrapping, Send keys, fingerprint phrases |
| `bitwarden` | HTTP API: encrypted payloads only, bounded reads, status codes as errors |
| `vault` | session, decrypted snapshot, name resolution, items, attachments, Sends, organization, search, checks |
| `access` | client tokens, per-client narrowing, throttling of failing sources |
| `links` | one-time link table |
| `mcpserver` | tools, views, link endpoints, audit log |
| `generate`, `totp` | passwords, one-time codes |
| `config`, `obs` | environment, logging, metrics, probes |

## Session

- Login with the personal API key (`client_credentials`). The token response carries the encrypted user and private keys and the KDF parameters.
- The salt is the account email: from the server's decryption options, else from the access token.
- KDF parameters outside safe bounds are refused.
- Keys are unwrapped again when a login returns different encrypted keys (key rotation).
- No refresh token: the session logs in again five minutes before expiry and after a 401.
- Failed logins back off from 15 s to 2 min; a cancelled caller does not count.
- The device id is derived from the client id, so restarts reuse one device.

## Snapshot

- Reads use a decrypted snapshot no older than `VWMCP_SYNC_TTL`; concurrent reads share one sync.
- A snapshot is stamped when its request leaves, so a finished write is visible to the next read.
- Writes are serialised, start from a fresh sync, send the revision date and sync again. If that last sync fails, the write still succeeds and the snapshot is dropped.
- A background sync every `VWMCP_REFRESH_INTERVAL` keeps readiness and metrics current.
- An undecryptable item or organization key is reported, not fatal. A URI with a wrong checksum is dropped.

## Writing

- Items are created directly in their collections.
- Fields are encrypted with the item key: the organization key, or a per-item key when the item has one.
- URIs carry checksums; passkeys and the autofill setting are carried through updates.
- A changed password, or a changed or removed hidden field, goes to the password history (five entries).
- Each attachment has its own key; the file name is encrypted with the item key. A failed upload removes its registration.
- Member and collection updates send group assignments back unchanged.

## Values leaving the process

| Path | Where the value goes |
|---|---|
| views | nowhere: no view type has a field for a secret value |
| `issue_value_link` | to the first fetch of the link |
| `share_with_human` | into a Send, encrypted with a key only the URL fragment holds |
| `get_secret`, `get_attachment` | to the model, only with `VWMCP_ALLOW_REVEAL` |

Secrets of items whose collection hides passwords, or marked for re-prompt, take no part in any of these, nor in fingerprints and copy detection.

## Organization

- Admin changes need write enabled and a client not narrowed to collections.
- Owner and admin roles are not granted, changed or removed without `VWMCP_ALLOW_ADMIN_ROLES`; invitations can be limited to domains.
- `confirm_member` returns the member's fingerprint phrase first — HKDF of SHA-256 of the public key with the user id, five words of the EFF list — and confirms only when called again with it.
