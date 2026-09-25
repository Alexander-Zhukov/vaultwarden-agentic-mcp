package keys

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // OAEP with SHA-1 is what the protocol specifies for wrapping organization keys
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// rsaBits is the key size every Bitwarden account uses.
const rsaBits = 2048

// ErrNotRSA is returned when key material decodes but is not an RSA key.
var ErrNotRSA = errors.New("not an RSA key")

// PrivateKey is an account's RSA key, used to unwrap organization keys shared
// with the account.
type PrivateKey struct {
	key *rsa.PrivateKey
}

// ParsePrivateKey reads a PKCS#8 DER private key, the form the server stores
// (encrypted) for every account.
func ParsePrivateKey(der []byte) (PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return PrivateKey{}, ErrNotRSA
	}
	return PrivateKey{key: key}, nil
}

// GeneratePrivateKey creates a new account key pair.
func GeneratePrivateKey() (PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("generate rsa key: %w", err)
	}
	return PrivateKey{key: key}, nil
}

// PKCS8 returns the DER encoding of the private key.
func (p PrivateKey) PKCS8() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return der, nil
}

// PublicSPKI returns the base64 DER SubjectPublicKeyInfo, the form the server
// hands out as a member's public key.
func (p PrivateKey) PublicSPKI() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// Decrypt unwraps an RSA EncString addressed to this key.
func (p PrivateKey) Decrypt(e EncString) ([]byte, error) {
	h, err := oaepHash(e.Type)
	if err != nil {
		return nil, err
	}
	out, err := rsa.DecryptOAEP(h, nil, p.key, e.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt: %w", err)
	}
	return out, nil
}

// DecryptKey unwraps a symmetric key, as organization keys are shared.
func (p PrivateKey) DecryptKey(s string) (SymmetricKey, error) {
	enc, err := ParseEncString(s)
	if err != nil {
		return SymmetricKey{}, err
	}
	material, err := p.Decrypt(enc)
	if err != nil {
		return SymmetricKey{}, err
	}
	return NewSymmetricKey(material)
}

// PublicKey is another account's key, used to share an organization key with it.
type PublicKey struct {
	key *rsa.PublicKey
}

// ParsePublicKey reads a base64 DER SubjectPublicKeyInfo.
func ParsePublicKey(spki string) (PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(spki)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: public key base64", ErrMalformed)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return PublicKey{}, fmt.Errorf("parse public key: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return PublicKey{}, ErrNotRSA
	}
	return PublicKey{key: key}, nil
}

// EncryptKey wraps a symmetric key for this public key with RSA-OAEP-SHA1
// (type 4), the type every client writes for organization key shares.
func (p PublicKey) EncryptKey(k SymmetricKey) (string, error) {
	data, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, p.key, k.Bytes(), nil) //nolint:gosec // protocol-mandated OAEP hash
	if err != nil {
		return "", fmt.Errorf("rsa encrypt: %w", err)
	}
	return EncString{Type: RSA2048OAEPSHA1, Data: data}.String(), nil
}

// Public returns the public half of the key pair.
func (p PrivateKey) Public() PublicKey { return PublicKey{key: &p.key.PublicKey} }

func oaepHash(t EncType) (hash.Hash, error) {
	switch t {
	case RSA2048OAEPSHA1, RSA2048OAEPSHA1HMACSHA256:
		return sha1.New(), nil //nolint:gosec // protocol-mandated OAEP hash
	case RSA2048OAEPSHA256, RSA2048OAEPSHA256HMACSHA2:
		return sha256.New(), nil
	case AESCBC256, AESCBC128HMACSHA256, AESCBC256HMACSHA256:
		return nil, fmt.Errorf("%w: %d with a private key", ErrUnsupported, t)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupported, t)
	}
}

// wordlist is the EFF long word list, the one Bitwarden draws fingerprint
// phrases from, one word per line in the list's own order.
//
//go:embed eff_large_wordlist.txt
var wordlist string

// phraseWords is how many words a fingerprint phrase has: five words of the
// 7776-word list carry the 64 bits the official clients require.
const phraseWords = 5

// FingerprintPhrase returns the phrase Bitwarden clients show for an account's
// public key, e.g. "wrench-uncle-breeze-scorn-vowel". The material is the
// account's user id. An operator confirming a member compares it with the
// phrase in the member's own client before trusting the key.
func (p PublicKey) FingerprintPhrase(material string) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(p.key)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	expanded, err := hkdf.Expand(sha256.New, sum[:], material, 32)
	if err != nil {
		return "", fmt.Errorf("expand fingerprint: %w", err)
	}
	words := strings.Split(strings.TrimSpace(wordlist), "\n")
	n := new(big.Int).SetBytes(expanded)
	size := big.NewInt(int64(len(words)))
	out := make([]string, phraseWords)
	for i := range out {
		var r big.Int
		n.DivMod(n, size, &r)
		out[i] = words[r.Int64()]
	}
	return strings.Join(out, "-"), nil
}
