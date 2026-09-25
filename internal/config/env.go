package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// envReader reads the environment and collects every problem it finds instead
// of failing on the first one: an operator fixing a fresh deployment should see
// the whole list at once, not one variable per restart.
//
// Values that can be guessed sensibly carry a default; values that cannot —
// which host to reach, as whom — are required. Either way every setting stays
// overridable from the environment, so nothing about a deployment is locked
// inside the binary.
type envReader struct {
	lookup   func(string) (string, bool)
	problems []string
	defaults []string
}

func (r *envReader) fail(name, reason string) {
	r.problems = append(r.problems, fmt.Sprintf("%s: %s", name, reason))
}

// err returns every collected problem as a single error, or nil when the
// environment is usable.
func (r *envReader) err() error {
	if len(r.problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  %s", ErrInvalidEnv, strings.Join(r.problems, "\n  "))
}

// Defaulted lists the variables that were not set and fell back to a default.
// The service logs them at startup so the effective configuration is visible
// without reading the source.
func (r *envReader) Defaulted() []string { return r.defaults }

func (r *envReader) value(name string) (string, bool) {
	raw, ok := r.lookup(name)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}

func (r *envReader) required(name string) string {
	value, ok := r.value(name)
	if !ok {
		r.fail(name, "required but not set")
		return ""
	}
	return value
}

// requiredSecret reads a credential, which never has a default.
func (r *envReader) requiredSecret(name string) Secret {
	return Secret(r.required(name))
}

func (r *envReader) noteDefault(name, value string) {
	r.defaults = append(r.defaults, name+"="+value)
}

func (r *envReader) stringOr(name, fallback string) string {
	value, ok := r.value(name)
	if !ok {
		r.noteDefault(name, fallback)
		return fallback
	}
	return value
}

func (r *envReader) intOr(name string, fallback int) int {
	raw, ok := r.value(name)
	if !ok {
		r.noteDefault(name, strconv.Itoa(fallback))
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		r.fail(name, "must be an integer")
		return fallback
	}
	return value
}

// capOr reads a limit where zero means "no limit" and anything below zero is a
// typo rather than an intention.
func (r *envReader) capOr(name string, fallback int) int {
	value := r.intOr(name, fallback)
	if value < 0 {
		r.fail(name, `must be zero (no limit) or a positive number`)
		return fallback
	}
	return value
}

// flag reads a switch. Every switch defaults to off: the safe end of each one
// is the absence of the capability it grants.
func (r *envReader) flag(name string) bool {
	raw, ok := r.value(name)
	if !ok {
		r.noteDefault(name, "false")
		return false
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		r.fail(name, "must be a boolean (true/false)")
		return false
	}
	return value
}

func (r *envReader) durationOr(name string, fallback time.Duration) time.Duration {
	raw, ok := r.value(name)
	if !ok {
		r.noteDefault(name, fallback.String())
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		r.fail(name, `must be a duration such as "30s" or "5m"`)
		return fallback
	}
	if value <= 0 {
		r.fail(name, "must be greater than zero")
		return fallback
	}
	return value
}

// listOr reads a comma-separated value. The "-" sentinel spells an empty list,
// so "no restriction" is always visible in the environment rather than implied
// by an empty string.
func (r *envReader) listOr(name string, fallback []string) []string {
	raw, ok := r.value(name)
	if !ok {
		r.noteDefault(name, describeList(fallback))
		return fallback
	}
	if raw == "-" {
		return nil
	}
	parts := strings.Split(raw, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	if len(items) == 0 {
		r.fail(name, `must list at least one value, or "-" to disable the restriction`)
		return fallback
	}
	return items
}

func describeList(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ",")
}
