package keys

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KDFType names the password-hashing function an account was set up with.
type KDFType int

const (
	// KDFPBKDF2 is PBKDF2-HMAC-SHA256, the historical default.
	KDFPBKDF2 KDFType = 0
	// KDFArgon2id is Argon2id, the default for accounts created since 2023.
	KDFArgon2id KDFType = 1
)

// KDF holds the parameters of an account's key derivation, as the server
// reports them. Memory is in MiB, as the protocol states it.
type KDF struct {
	Type        KDFType
	Iterations  int
	Memory      int
	Parallelism int
}

// Bounds outside which a server-reported KDF is refused: below them a
// compromised server could ask for a trivially weak derivation, above them for
// one that stalls every login.
const (
	minPBKDF2Iterations = 5000
	maxPBKDF2Iterations = 2_000_000
	minArgon2Iterations = 2
	maxArgon2Iterations = 10
	minArgon2MemoryMiB  = 16
	maxArgon2MemoryMiB  = 1024
	maxArgon2Threads    = 16
)

// Validate refuses parameters no Bitwarden client would accept.
func (k KDF) Validate() error {
	switch k.Type {
	case KDFPBKDF2:
		if k.Iterations < minPBKDF2Iterations || k.Iterations > maxPBKDF2Iterations {
			return fmt.Errorf("%w: PBKDF2 with %d iterations", ErrUnsupported, k.Iterations)
		}
	case KDFArgon2id:
		if k.Iterations < minArgon2Iterations || k.Iterations > maxArgon2Iterations ||
			k.Memory < minArgon2MemoryMiB || k.Memory > maxArgon2MemoryMiB ||
			k.Parallelism < 1 || k.Parallelism > maxArgon2Threads {
			return fmt.Errorf("%w: Argon2id t=%d m=%dMiB p=%d", ErrUnsupported, k.Iterations, k.Memory, k.Parallelism)
		}
	default:
		return fmt.Errorf("%w: KDF type %d", ErrUnsupported, k.Type)
	}
	return nil
}

// MasterKey derives the 32-byte master key from the master password. The salt
// is the account email, normalised the way every Bitwarden client does it.
func MasterKey(password, email string, kdf KDF) ([]byte, error) {
	if err := kdf.Validate(); err != nil {
		return nil, err
	}
	salt := strings.ToLower(strings.TrimSpace(email))
	switch kdf.Type {
	case KDFPBKDF2:
		key, err := pbkdf2.Key(sha256.New, password, []byte(salt), kdf.Iterations, encKeySize)
		if err != nil {
			return nil, fmt.Errorf("derive pbkdf2: %w", err)
		}
		return key, nil
	case KDFArgon2id:
		digest := sha256.Sum256([]byte(salt))
		// Validate bounds every parameter to a small positive range, so the
		// conversions cannot overflow.
		iterations := uint32(kdf.Iterations) //nolint:gosec // bounded by Validate
		memory := uint32(kdf.Memory) * 1024  //nolint:gosec // bounded by Validate
		threads := uint8(kdf.Parallelism)    //nolint:gosec // bounded by Validate
		return argon2.IDKey([]byte(password), digest[:], iterations, memory, threads, encKeySize), nil
	default:
		return nil, fmt.Errorf("%w: KDF type %d", ErrUnsupported, kdf.Type)
	}
}

// StretchMasterKey expands the master key into the key pair that wraps the
// account's user key.
func StretchMasterKey(masterKey []byte) (SymmetricKey, error) {
	enc, err := hkdf.Expand(sha256.New, masterKey, "enc", encKeySize)
	if err != nil {
		return SymmetricKey{}, fmt.Errorf("expand enc key: %w", err)
	}
	mac, err := hkdf.Expand(sha256.New, masterKey, "mac", macKeySize)
	if err != nil {
		return SymmetricKey{}, fmt.Errorf("expand mac key: %w", err)
	}
	return NewSymmetricKey(append(enc, mac...))
}

// MasterPasswordHash is the proof of the master password the server checks on
// password login and on account operations. It is derived from the master key,
// so the password itself never leaves the client.
func MasterPasswordHash(masterKey []byte, password string) (string, error) {
	hash, err := pbkdf2.Key(sha256.New, string(masterKey), []byte(password), 1, encKeySize)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}
	return base64.StdEncoding.EncodeToString(hash), nil
}

// SendKey derives the key that encrypts a Send from its 16-byte seed. The seed
// travels in the URL fragment of the share link, never to the server.
func SendKey(seed []byte) (SymmetricKey, error) {
	material, err := hkdf.Key(sha256.New, seed, []byte("bitwarden-send"), "send", encKeySize+macKeySize)
	if err != nil {
		return SymmetricKey{}, fmt.Errorf("derive send key: %w", err)
	}
	return NewSymmetricKey(material)
}
