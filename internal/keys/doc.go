// Package keys implements the client-side cryptography of the Bitwarden
// protocol: deriving the master key from a password, the encrypted string
// format every vault field travels in, the encrypted buffer attachments use,
// and the RSA key wrapping that shares organization keys between members.
//
// The server never sees a plaintext value. Everything a Vaultwarden instance
// stores is encrypted here first, with keys that exist only in this process.
package keys
