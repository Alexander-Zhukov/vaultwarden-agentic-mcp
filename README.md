# Vaultwarden Agentic MCP

**English** · [Русский](README.ru.md)

[Model Context Protocol](https://modelcontextprotocol.io/) server for [Vaultwarden](https://github.com/dani-garcia/vaultwarden). Gives AI agents a vault account while keeping secret values out of the model's context.

Tools return names, metadata and fingerprints. Values reach programs through one-time links, humans through Bitwarden Send, and the vault through upload links. Returning a value to the model is a separate, opt-in tool.

Encryption is done in the server, as in the official clients; Vaultwarden stores only ciphertext.

## Tools

| Tool | Description |
|---|---|
| `get_status` | Account, mode, visible collections, enabled capabilities |
| `list_collections` | Collections with their organization, item counts and access, optionally of one organization; members in admin mode |
| `list_items` | Item metadata by collection, type or trash |
| `search_items` | Find items by name, username, URI, notes, field names; never searches values |
| `get_item` | Everything except secret values: notes, fields, attachments, SSH public key, fingerprints |
| `find_by_value` | Items holding a value the agent already has (≥ 8 characters, rate-limited) |
| `find_copies` | Other items holding the same secret |
| `check_items` | Notes convention, expired or expiring items, empty items, duplicates, undecryptable items |
| `issue_value_link` | One-time URL returning one value or attachment |
| `request_value_upload` | One-time URL through which a human or a program stores a value or a file |
| `share_with_human` | Bitwarden Send link for a value |
| `revoke_share` | Delete a Send link this client created |
| `create_item` | Create in a collection; password given, generated server-side or uploaded |
| `update_item` | Change fields; a changed password or hidden field goes to the history |
| `delete_item` | Move to trash, or delete permanently where enabled |
| `restore_item` | Restore from trash |
| `add_attachment` | Attach a file |
| `delete_attachment` | Remove an attachment |
| `get_secret` | Return one value to the model |
| `get_attachment` | Return an attachment to the model |
| `list_organizations` | Admin: the account's organizations, its role, which ones this instance manages |
| `list_members` | Admin: members, roles, collection access |
| `invite_member` | Admin: invite with a role and collections |
| `confirm_member` | Admin: confirm after comparing the fingerprint phrase |
| `update_member` | Admin: change role or collection access |
| `change_member` | Admin: revoke, restore or remove |
| `create_collection` | Admin: create a collection |
| `update_collection` | Admin: rename or change access |
| `delete_collection` | Admin: delete an empty collection |
| `set_item_collections` | Admin: move an item between collections |
| `list_events` | Admin: organization event log |

Admin tools take an `organization` argument when the instance manages several.

Server mode has a tool set of its own:

| Tool | Description |
|---|---|
| `get_status` | Server, account and organization counts, enabled capabilities |
| `list_users` | Accounts with status, two-step login, last activity, organizations |
| `get_user` | One account by email or id |
| `list_organizations` | Organizations of the server with their confirmed members and owners |
| `invite_user` | Invited account for an address, so the person can register with sign-ups closed |
| `change_user` | Disable, enable, end every session, resend the invitation |
| `delete_user` | Delete an account; two calls with a confirmation code, refused for the last confirmed owner or member of an organization |
| `delete_organization` | Delete an organization with its contents; two calls with a confirmation code |

The admin panel reports confirmed memberships only: an organization without a confirmed member is not listed, and is deleted by id.

Tools of a disabled capability are not registered. Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`).

## Values out of context

```
issue_value_link(item="CI_TOKEN")        →  curl -s <url> | gh auth login --with-token
request_value_upload(item="API_KEY")     →  a human opens the URL, or: printf %s "$V" | curl -X PUT --data-binary @- <url>
create_item(..., generate_password={})   →  generated and stored server-side, never shown
share_with_human(item="WIFI", max_access=1)
```

- **One-time links** are 256-bit tokens in memory: one use, a few minutes, gone on restart. The link's item is checked again against the issuing client's collections when it is redeemed. `VWMCP_LINK_SOURCES` limits the addresses that may redeem.
- **Uploaded values** always land in a secret field: `password`, `totp`, `ssh_private_key`, a hidden custom field, or the text of a note item.
- **TOTP seeds** never leave the server; `totp` is the current code.
- **Fingerprints** are HMACs under a key derived from the account's user key: equal values give equal fingerprints within the account, and a fingerprint cannot be brute-forced by anyone who only sees it.
- Items whose collection hides passwords, or marked for master-password re-prompt, give out no values.

## Accounts, instances, clients

A consumer or admin process serves one Vaultwarden account; the account's membership is the boundary of what it can reach. Several agents may share an instance with their own bearer tokens, each optionally narrowed to read-only use or to some collections.

| Mode | Acts as | Does |
|---|---|---|
| `consumer` | an account | items of its collections |
| `admin` | an owner or admin account | also members, collections and events of its organizations; `VWMCP_ORGANIZATION` narrows which |
| `server` | the admin token | accounts and organizations of the whole server, through the admin panel; no vault contents |

A server-mode instance holds the key to every account of the server; run it separately from the vault instances, with its own clients.

## Setup

### Prerequisites

- Vaultwarden (tested with 1.36)
- An account with a personal API key (Settings → Security → Keys → API key) and its master password; for server mode, the server's `ADMIN_TOKEN` instead

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `VWMCP_SERVER_URL` | Yes | — | Vaultwarden URL |
| `VWMCP_CLIENT_ID` | Yes, not in server mode | — | API key client id (`user.<uuid>`) |
| `VWMCP_CLIENT_SECRET` | Yes, not in server mode | — | API key client secret |
| `VWMCP_MASTER_PASSWORD` | Yes, not in server mode | — | Master password |
| `VWMCP_ADMIN_TOKEN` | Server mode only | — | The server's `ADMIN_TOKEN` in plain form |
| `VWMCP_CLIENTS` | Yes (http) | — | `name:sha256(token)[:read_only][:collections=a\|b]`, comma-separated |
| `VWMCP_MODE` | No | `consumer` | `consumer`, `admin` or `server` |
| `VWMCP_ORGANIZATION` | No | all | Organizations admin mode manages: exact names or ids, comma-separated |
| `VWMCP_ALLOW_WRITE` | No | `false` | Create, change and delete items; admin changes; in server mode, invitations and account changes |
| `VWMCP_ALLOW_SHARE` | No | `false` | `share_with_human` (with write) |
| `VWMCP_ALLOW_REVEAL` | No | `false` | `get_secret`, `get_attachment` |
| `VWMCP_ALLOW_PERMANENT_DELETE` | No | `false` | Delete without the trash; in server mode, delete accounts and organizations |
| `VWMCP_ALLOW_ADMIN_ROLES` | No | `false` | Grant or change owner and admin |
| `VWMCP_INVITE_DOMAINS` | No | any | Domains `invite_member` and `invite_user` may invite |
| `VWMCP_PUBLIC_URL` | No | — | How clients reach this server; enables one-time links |
| `VWMCP_LINK_SOURCES` | No | any | Addresses or CIDRs allowed to redeem links |
| `VWMCP_NOTES_PREFIXES` | No | — | Lines every item's notes must have, for `check_items` |
| `VWMCP_TRANSPORT` | No | `http` | `http` or `stdio` |
| `VWMCP_LISTEN_ADDR` | No | `:8080` | Listener for `/mcp`, links, `/health`, `/ready`, `/metrics` |

The rest — timeouts, TTLs, limits, TLS — is listed with defaults in [`env.example`](env.example). Widening settings and every defaulted variable are logged at startup.

A client token and its hash:

```bash
docker run --rm alexfail2/vaultwarden-agentic-mcp token
```

### Run with Docker

Images for `linux/amd64` and `linux/arm64`: [`alexfail2/vaultwarden-agentic-mcp`](https://hub.docker.com/r/alexfail2/vaultwarden-agentic-mcp).

```bash
docker run -d \
  -e VWMCP_SERVER_URL=https://vault.example.com \
  -e VWMCP_CLIENT_ID=user.00000000-0000-0000-0000-000000000000 \
  -e VWMCP_CLIENT_SECRET=... \
  -e VWMCP_MASTER_PASSWORD=... \
  -e VWMCP_CLIENTS=agent:<sha256> \
  -e VWMCP_PUBLIC_URL=http://mcp.example.lan:8080 \
  -p 8080:8080 \
  alexfail2/vaultwarden-agentic-mcp
```

### Build from source

```bash
git clone https://github.com/Alexander-Zhukov/vaultwarden-agentic-mcp.git
cd vaultwarden-agentic-mcp
make build                   # ./bin/vaultwarden-agentic-mcp
docker build -t vaultwarden-agentic-mcp .
```

## MCP client configuration

```json
{
  "mcpServers": {
    "secrets": {
      "type": "http",
      "url": "http://mcp.example.lan:8080/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Endpoints

| Path | |
|---|---|
| `/mcp` | Streamable HTTP, bearer token |
| `/v1/links/{token}`, `/v1/upload/{token}` | One-time links |
| `/health` | Process is alive |
| `/ready` | Logged in and the last sync succeeded; in server mode, the last admin panel check |
| `/metrics` | Prometheus; expiry is exported as counts, without item names |

## How it works

The server logs in with the account's API key, derives the master key (PBKDF2 or Argon2id) and unwraps the user, private and organization keys. It keeps a decrypted snapshot of the vault for a short TTL and syncs again before every write; writes carry the item's revision date, so a change made elsewhere is refused rather than overwritten. Items, attachments and Sends are encrypted in the server with the same formats as the official clients. Only authenticated ciphertext is decrypted. Details: [`doc/architecture.md`](doc/architecture.md).

## Development

```bash
make check-all         # format, vet, lint, tidy, race tests with coverage gate, govulncheck
make test-integration  # against Vaultwarden in Docker, cross-checked with the official Bitwarden CLI
```

The unit tests drive every tool over HTTP against an in-memory fake of the server.

A `v*` tag builds and pushes the image; changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE). The fingerprint phrase word list is the
[EFF long word list](https://www.eff.org/dice) (CC BY 3.0 US).
