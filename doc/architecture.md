# Architecture

```
MCP client ──bearer──> /mcp ──> mcpserver ──> vault ──> keys
program ─────────────> /v1/links, /v1/upload ─┘ │  └───> bitwarden ──> Vaultwarden
                                                └──> vwadmin ──> Vaultwarden /admin   (server mode)
```

| Package | Responsibility |
|---|---|
| `keys` | master key (PBKDF2, Argon2id), EncString and attachment buffers, RSA-OAEP key wrapping, Send keys, fingerprint phrases |
| `bitwarden` | HTTP API: encrypted payloads only, bounded reads, status codes as errors |
| `vwadmin` | admin panel of the server mode: token login, session cookie, accounts and organizations |
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

- Admin mode manages every organization the account owns or administers, within `VWMCP_ORGANIZATION`. With one such organization the tools need no argument; with several they take `organization`.
- `VWMCP_ORGANIZATION` matches exactly: an id-shaped entry only an id, a name only one organization of exactly that name. Anyone on the server can create an organization and invite this account, so look-alike names never widen the list. An id given to a tool wins over names.
- Collection names are looked up within the organization being managed; names repeat across organizations.
- A manager of every collection is the custom type with three permissions in Vaultwarden; updates send it back that way, since the server derives the access from them.
- `set_item_collections` acts in the item's own organization and never moves an item to another one.
- Admin changes need write enabled and a client not narrowed to collections.
- Owner and admin roles are not granted, changed or removed without `VWMCP_ALLOW_ADMIN_ROLES`; invitations can be limited to domains.
- `confirm_member` returns the member's fingerprint phrase first — HKDF of SHA-256 of the public key with the user id, five words of the EFF list — and confirms only when called again with it.

## Server mode

- No account and no vault: the instance logs in to `/admin` with the admin token and keeps the session cookie. A refused session is renewed once, shared by concurrent requests. A failed login is answered from memory until a growing backoff has passed: the server throttles panel logins (a burst of three, then one per five minutes) and logs every refused token.
- The panel routes its POST actions only for a JSON content type; every action sends one.
- The panel lists no organizations a program can read; they are collected from the organizations of every account, which the panel reports for confirmed memberships only. An organization without a confirmed member is therefore not listed; `delete_organization` takes its id.
- The panel's configuration dump carries the server's secrets (admin token, SMTP and Duo keys) and has no tool.
- `delete_user` and `delete_organization` act in two calls: the first returns a random code bound to the tool, the target and the client, valid for five minutes and once; the second must bring it back. A code cannot be derived from the target, so an agent cannot skip the first look.
- `delete_user` refuses the last confirmed owner of an organization (the server refuses it too) and its last confirmed member, whose deletion would leave the organization unlisted.
- Every setting that needs an account — the account key, organizations, links, reveal, share, checks and the sync and link tuning — and collection-narrowed clients are refused at startup rather than ignored.
