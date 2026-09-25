# Changelog

## v1.1.0

### Added
- Admin mode manages every organization the account owns or administers.
  Admin tools take `organization` when there are several; `list_organizations`
  shows the account's organizations and which ones the instance manages;
  `list_collections` names each collection's organization and can be filtered
  by it. `VWMCP_ORGANIZATION` takes a comma-separated list to narrow them.
- Server mode (`VWMCP_MODE=server`, `VWMCP_ADMIN_TOKEN`): the accounts and
  organizations of the whole server through the Vaultwarden admin panel.
  `list_users`, `get_user` and `list_organizations`; `invite_user` and
  `change_user` (disable, enable, deauthorize, resend the invitation) with
  `VWMCP_ALLOW_WRITE`; `delete_user` and `delete_organization`, each in two
  steps, with `VWMCP_ALLOW_PERMANENT_DELETE`.

### Fixed
- `list_organizations` had no annotation class and would have been announced as
  destructive; a test now covers every tool of every mode.

## v1.0.0

First release.

- 30 tools over one Vaultwarden account: reading and searching items without
  values, value fingerprints, finding items by a known value, vault checks,
  writing items and attachments, trash, and organization management in admin
  mode (members, collections, event log).
- Values leave the server through one-time links for programs, upload links
  for humans and programs, and Bitwarden Send; returning a value to the model
  is a separate switch, off by default.
- Bitwarden encryption in the server: PBKDF2 and Argon2id master keys, per-item
  and attachment keys, authenticated ciphertext only, key rotation.
- Consumer and admin modes; capability switches for writing, sharing,
  revealing, permanent deletion and admin roles, all off by default.
- Several clients per instance with their own bearer tokens, optionally
  read-only or narrowed to collections.
- Streamable HTTP and stdio transports, MCP tool annotations, Prometheus
  metrics, health and readiness probes.
