# Changelog

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
