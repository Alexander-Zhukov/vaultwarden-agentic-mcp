package keys

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// EncType is the header of an encrypted value, naming the algorithm.
type EncType int

// Encryption types of the Bitwarden protocol. Types 1 (AES-128) and the RSA
// variants with an HMAC are obsolete and appear only in very old vaults.
const (
	AESCBC256                 EncType = 0
	AESCBC128HMACSHA256       EncType = 1
	AESCBC256HMACSHA256       EncType = 2
	RSA2048OAEPSHA256         EncType = 3
	RSA2048OAEPSHA1           EncType = 4
	RSA2048OAEPSHA256HMACSHA2 EncType = 5
	RSA2048OAEPSHA1HMACSHA256 EncType = 6
)

// isRSA reports whether the type wraps data with a public key.
func (t EncType) isRSA() bool {
	switch t {
	case RSA2048OAEPSHA256, RSA2048OAEPSHA1, RSA2048OAEPSHA256HMACSHA2, RSA2048OAEPSHA1HMACSHA256:
		return true
	case AESCBC256, AESCBC128HMACSHA256, AESCBC256HMACSHA256:
		return false
	default:
		return false
	}
}

// EncString is an encrypted value in its parsed form. Its wire form is
// "<type>.<iv>|<data>|<mac>" for symmetric types and "<type>.<data>" for RSA,
// every part base64.
type EncString struct {
	Type EncType
	IV   []byte
	Data []byte
	MAC  []byte
}

// ParseEncString parses the wire form. A value without a type header is the
// pre-2018 layout — three parts mean type 1, two mean type 0 — and is parsed
// only so that decryption can refuse it with a clear error.
func ParseEncString(s string) (EncString, error) {
	if s == "" {
		return EncString{}, fmt.Errorf("%w: empty", ErrMalformed)
	}
	var enc EncString
	body := s
	if header, rest, ok := strings.Cut(s, "."); ok {
		t, err := strconv.Atoi(header)
		if err != nil {
			return EncString{}, fmt.Errorf("%w: type header", ErrMalformed)
		}
		enc.Type = EncType(t)
		body = rest
	} else {
		enc.Type = AESCBC128HMACSHA256
		if strings.Count(s, "|") == 1 {
			enc.Type = AESCBC256
		}
	}
	parts := strings.Split(body, "|")

	var err error
	switch enc.Type {
	case AESCBC256:
		if len(parts) != 2 {
			return EncString{}, fmt.Errorf("%w: type 0 needs 2 parts, got %d", ErrMalformed, len(parts))
		}
		enc.IV, err = decodePart(parts[0])
		if err == nil {
			enc.Data, err = decodePart(parts[1])
		}
	case AESCBC128HMACSHA256, AESCBC256HMACSHA256:
		if len(parts) != 3 {
			return EncString{}, fmt.Errorf("%w: type %d needs 3 parts, got %d", ErrMalformed, enc.Type, len(parts))
		}
		enc.IV, err = decodePart(parts[0])
		if err == nil {
			enc.Data, err = decodePart(parts[1])
		}
		if err == nil {
			enc.MAC, err = decodePart(parts[2])
		}
	case RSA2048OAEPSHA256, RSA2048OAEPSHA1:
		if len(parts) != 1 {
			return EncString{}, fmt.Errorf("%w: type %d needs 1 part, got %d", ErrMalformed, enc.Type, len(parts))
		}
		enc.Data, err = decodePart(parts[0])
	case RSA2048OAEPSHA256HMACSHA2, RSA2048OAEPSHA1HMACSHA256:
		if len(parts) != 2 {
			return EncString{}, fmt.Errorf("%w: type %d needs 2 parts, got %d", ErrMalformed, enc.Type, len(parts))
		}
		enc.Data, err = decodePart(parts[0])
		if err == nil {
			enc.MAC, err = decodePart(parts[1])
		}
	default:
		return EncString{}, fmt.Errorf("%w: type %d", ErrUnsupported, enc.Type)
	}
	if err != nil {
		return EncString{}, err
	}
	return enc, nil
}

// String renders the wire form.
func (e EncString) String() string {
	b64 := base64.StdEncoding.EncodeToString
	head := strconv.Itoa(int(e.Type)) + "."
	switch {
	case e.Type.isRSA() && len(e.MAC) > 0:
		return head + b64(e.Data) + "|" + b64(e.MAC)
	case e.Type.isRSA():
		return head + b64(e.Data)
	case e.Type == AESCBC256:
		return head + b64(e.IV) + "|" + b64(e.Data)
	default:
		return head + b64(e.IV) + "|" + b64(e.Data) + "|" + b64(e.MAC)
	}
}

func decodePart(s string) ([]byte, error) {
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: base64", ErrMalformed)
	}
	return out, nil
}
