// Package generate makes random passwords server-side, so a fresh secret can
// be stored without ever passing through the model.
package generate

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Character classes. Ambiguous glyphs (0/O, 1/l/I) are left out of the
// defaults because generated secrets are sometimes typed by a human.
const (
	lower   = "abcdefghijkmnopqrstuvwxyz"
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digits  = "23456789"
	symbols = "!@#$%^&*-_=+"
)

// Limits on a generated password.
const (
	MinLength = 12
	MaxLength = 256
)

// ErrPolicy is returned for a policy that cannot produce a password.
var ErrPolicy = errors.New("invalid password policy")

// Policy describes a password. The zero value of each class switch means "on";
// callers turn classes off explicitly.
type Policy struct {
	Length    int
	NoUpper   bool
	NoDigits  bool
	NoSymbols bool
}

// Password returns a password with at least one character of every enabled
// class, drawn from crypto/rand without modulo bias.
func Password(p Policy) (string, error) {
	if p.Length < MinLength || p.Length > MaxLength {
		return "", fmt.Errorf("%w: length %d, want %d..%d", ErrPolicy, p.Length, MinLength, MaxLength)
	}
	classes := []string{lower}
	if !p.NoUpper {
		classes = append(classes, upper)
	}
	if !p.NoDigits {
		classes = append(classes, digits)
	}
	if !p.NoSymbols {
		classes = append(classes, symbols)
	}
	all := strings.Join(classes, "")

	out := make([]byte, p.Length)
	for i, class := range classes {
		c, err := pick(class)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	for i := len(classes); i < p.Length; i++ {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	// The guaranteed characters sit at the front until shuffled.
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("read random: %w", err)
		}
		k := j.Int64()
		out[i], out[k] = out[k], out[i]
	}
	return string(out), nil
}

func pick(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, fmt.Errorf("read random: %w", err)
	}
	return set[n.Int64()], nil
}
