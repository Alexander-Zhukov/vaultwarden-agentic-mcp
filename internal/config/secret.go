package config

import (
	"encoding/json"
	"log/slog"
)

// redacted replaces every secret value in any human- or machine-readable output.
const redacted = "[REDACTED]"

// Secret is a string that never reveals itself through printing, logging or
// JSON encoding. Only Reveal returns the underlying value, which makes every
// leak of a credential an explicit, greppable call.
type Secret string

// String implements fmt.Stringer so that %v and %s cannot leak the value.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer so that %#v cannot leak the value.
func (s Secret) GoString() string { return redacted }

// MarshalJSON makes struct dumps safe: the field is present but never readable.
func (s Secret) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(redacted)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// LogValue keeps the value out of slog attributes, including slog.Any on a
// whole config struct.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// Reveal returns the underlying secret. Call it only where the value is handed
// to the service that needs it.
func (s Secret) Reveal() string { return string(s) }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s == "" }
