// Package totp computes one-time codes from the seeds stored in login items,
// so an agent can pass a second factor without ever holding the seed.
package totp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 defaults to HMAC-SHA1
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrSeed is returned for a seed that cannot be parsed.
var ErrSeed = errors.New("invalid TOTP seed")

// steamAlphabet is the character set of Steam Guard codes.
const steamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"

// Params describe how codes are derived from a seed.
type Params struct {
	secret    []byte
	algorithm func() hash.Hash
	digits    int
	period    int
	steam     bool
}

// Code is a one-time code and how long it stays valid.
type Code struct {
	Code      string
	ExpiresIn time.Duration
	Period    time.Duration
}

// Parse reads a seed in any form Bitwarden stores: an otpauth:// URI, a
// steam:// seed, or a bare base32 secret.
func Parse(seed string) (Params, error) {
	seed = strings.TrimSpace(seed)
	p := Params{algorithm: sha1.New, digits: 6, period: 30}
	secret := seed
	switch {
	case strings.HasPrefix(strings.ToLower(seed), "otpauth://"):
		u, err := url.Parse(seed)
		if err != nil {
			// The parse error quotes the whole URI, secret included.
			return Params{}, fmt.Errorf("%w: the otpauth URI does not parse", ErrSeed)
		}
		q := u.Query()
		secret = q.Get("secret")
		if d := q.Get("digits"); d != "" {
			n, err := strconv.Atoi(d)
			if err != nil || n < 6 || n > 10 {
				return Params{}, fmt.Errorf("%w: digits %q", ErrSeed, d)
			}
			p.digits = n
		}
		if s := q.Get("period"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > 300 {
				return Params{}, fmt.Errorf("%w: period %q", ErrSeed, s)
			}
			p.period = n
		}
		switch strings.ToUpper(q.Get("algorithm")) {
		case "", "SHA1":
		case "SHA256":
			p.algorithm = sha256.New
		case "SHA512":
			p.algorithm = sha512.New
		default:
			return Params{}, fmt.Errorf("%w: algorithm %q", ErrSeed, q.Get("algorithm"))
		}
	case strings.HasPrefix(strings.ToLower(seed), "steam://"):
		secret = seed[len("steam://"):]
		p.steam, p.digits = true, 5
	}
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(clean, "="))
	if err != nil || len(key) == 0 {
		return Params{}, fmt.Errorf("%w: secret is not base32", ErrSeed)
	}
	p.secret = key
	return p, nil
}

// At returns the code valid at a moment.
func (p Params) At(t time.Time) Code {
	period := int64(p.period)
	unix := t.Unix()
	counter := uint64(unix / period) //nolint:gosec // unix time after 1970 is positive
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(p.algorithm, p.secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := uint64(binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff)

	var code string
	if p.steam {
		var b strings.Builder
		for range p.digits {
			b.WriteByte(steamAlphabet[value%uint64(len(steamAlphabet))])
			value /= uint64(len(steamAlphabet))
		}
		code = b.String()
	} else {
		mod := uint64(1)
		for range p.digits {
			mod *= 10
		}
		code = fmt.Sprintf("%0*d", p.digits, value%mod)
	}
	remaining := period - unix%period
	return Code{Code: code, ExpiresIn: time.Duration(remaining) * time.Second, Period: time.Duration(period) * time.Second}
}
