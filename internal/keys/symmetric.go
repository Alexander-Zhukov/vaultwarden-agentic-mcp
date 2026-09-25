package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	encKeySize = 32
	macKeySize = 32
	blockSize  = aes.BlockSize
)

// Errors a caller may need to tell apart: a wrong key and damaged data look the
// same from the outside, and neither should be retried.
var (
	ErrKeySize     = errors.New("invalid key size")
	ErrMAC         = errors.New("message authentication failed")
	ErrPadding     = errors.New("invalid padding")
	ErrUnsupported = errors.New("unsupported encryption type")
	ErrMalformed   = errors.New("malformed encrypted value")
)

// SymmetricKey is an AES-256-CBC key paired with an HMAC-SHA256 key, the pair
// Bitwarden uses for user, organization, item and attachment keys alike.
type SymmetricKey struct {
	enc []byte
	mac []byte
}

// NewSymmetricKey splits 64 bytes of key material into its encryption and MAC
// halves.
func NewSymmetricKey(material []byte) (SymmetricKey, error) {
	if len(material) != encKeySize+macKeySize {
		return SymmetricKey{}, fmt.Errorf("%w: %d bytes, want %d", ErrKeySize, len(material), encKeySize+macKeySize)
	}
	return SymmetricKey{
		enc: bytes.Clone(material[:encKeySize]),
		mac: bytes.Clone(material[encKeySize:]),
	}, nil
}

// GenerateSymmetricKey returns a fresh random key.
func GenerateSymmetricKey() (SymmetricKey, error) {
	material := make([]byte, encKeySize+macKeySize)
	if _, err := rand.Read(material); err != nil {
		return SymmetricKey{}, fmt.Errorf("read random key: %w", err)
	}
	return NewSymmetricKey(material)
}

// Bytes returns the 64-byte key material, encryption half first — the form in
// which a key is itself encrypted and stored.
func (k SymmetricKey) Bytes() []byte {
	out := make([]byte, 0, len(k.enc)+len(k.mac))
	out = append(out, k.enc...)
	return append(out, k.mac...)
}

// IsZero reports whether the key was never set.
func (k SymmetricKey) IsZero() bool { return len(k.enc) == 0 }

// Encrypt seals plaintext as an EncString of type 2 (AES-256-CBC with an
// HMAC-SHA256 over the IV and ciphertext), the only type written today.
func (k SymmetricKey) Encrypt(plaintext []byte) (EncString, error) {
	if k.IsZero() {
		return EncString{}, fmt.Errorf("%w: empty key", ErrKeySize)
	}
	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return EncString{}, fmt.Errorf("read random iv: %w", err)
	}
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return EncString{}, fmt.Errorf("init aes: %w", err)
	}
	padded := pad(plaintext)
	data := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, padded)
	return EncString{
		Type: AESCBC256HMACSHA256,
		IV:   iv,
		Data: data,
		MAC:  k.sign(iv, data),
	}, nil
}

// EncryptString is Encrypt for text, returning the wire form.
func (k SymmetricKey) EncryptString(plaintext string) (string, error) {
	enc, err := k.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return enc.String(), nil
}

// Decrypt opens an EncString. The MAC is verified before any decryption, so a
// tampered or foreign value is rejected without touching the cipher.
func (k SymmetricKey) Decrypt(e EncString) ([]byte, error) {
	if k.IsZero() {
		return nil, fmt.Errorf("%w: empty key", ErrKeySize)
	}
	// Only authenticated values are opened. Accepting a value without a MAC
	// under a key that has one would let whoever stores the data strip the
	// MAC and flip plaintext bits, which is why the official clients refuse
	// it too.
	if e.Type != AESCBC256HMACSHA256 {
		return nil, fmt.Errorf("%w: type %d with an authenticated key (legacy encryption is not supported)", ErrUnsupported, e.Type)
	}
	if !hmac.Equal(e.MAC, k.sign(e.IV, e.Data)) {
		return nil, ErrMAC
	}
	if len(e.IV) != blockSize || len(e.Data) == 0 || len(e.Data)%blockSize != 0 {
		return nil, fmt.Errorf("%w: bad iv or block length", ErrMalformed)
	}
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return nil, fmt.Errorf("init aes: %w", err)
	}
	out := make([]byte, len(e.Data))
	cipher.NewCBCDecrypter(block, e.IV).CryptBlocks(out, e.Data)
	return unpad(out)
}

// DecryptString parses and opens a wire-form EncString as text.
func (k SymmetricKey) DecryptString(s string) (string, error) {
	enc, err := ParseEncString(s)
	if err != nil {
		return "", err
	}
	plain, err := k.Decrypt(enc)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// DecryptKey opens an EncString that wraps another symmetric key.
func (k SymmetricKey) DecryptKey(s string) (SymmetricKey, error) {
	enc, err := ParseEncString(s)
	if err != nil {
		return SymmetricKey{}, err
	}
	material, err := k.Decrypt(enc)
	if err != nil {
		return SymmetricKey{}, err
	}
	return NewSymmetricKey(material)
}

// EncryptKey wraps another symmetric key under this one.
func (k SymmetricKey) EncryptKey(inner SymmetricKey) (string, error) {
	enc, err := k.Encrypt(inner.Bytes())
	if err != nil {
		return "", err
	}
	return enc.String(), nil
}

// EncryptBuffer seals binary data in the layout attachments are stored in: one
// type byte, the IV, the MAC, then the ciphertext.
func (k SymmetricKey) EncryptBuffer(plaintext []byte) ([]byte, error) {
	enc, err := k.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(enc.IV)+len(enc.MAC)+len(enc.Data))
	out = append(out, byte(AESCBC256HMACSHA256))
	out = append(out, enc.IV...)
	out = append(out, enc.MAC...)
	return append(out, enc.Data...), nil
}

// DecryptBuffer opens data produced by EncryptBuffer or any Bitwarden client.
func (k SymmetricKey) DecryptBuffer(buf []byte) ([]byte, error) {
	const header = 1 + blockSize + sha256.Size
	if len(buf) < header+blockSize {
		return nil, fmt.Errorf("%w: buffer of %d bytes", ErrMalformed, len(buf))
	}
	if EncType(buf[0]) != AESCBC256HMACSHA256 {
		return nil, fmt.Errorf("%w: buffer type %d", ErrUnsupported, buf[0])
	}
	return k.Decrypt(EncString{
		Type: AESCBC256HMACSHA256,
		IV:   buf[1 : 1+blockSize],
		MAC:  buf[1+blockSize : header],
		Data: buf[header:],
	})
}

func (k SymmetricKey) sign(iv, data []byte) []byte {
	h := hmac.New(sha256.New, k.mac)
	h.Write(iv)
	h.Write(data)
	return h.Sum(nil)
}

// pad applies PKCS#7 padding.
func pad(data []byte) []byte {
	n := blockSize - len(data)%blockSize
	out := make([]byte, len(data), len(data)+n)
	copy(out, data)
	return append(out, bytes.Repeat([]byte{byte(n)}, n)...)
}

// unpad strips PKCS#7 padding, rejecting anything that is not well formed.
func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrPadding
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, ErrPadding
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, ErrPadding
		}
	}
	return data[:len(data)-n], nil
}
