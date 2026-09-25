package generate

import (
	"errors"
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		policy Policy
		want   []string
		absent []string
	}{
		{"all classes", Policy{Length: 32}, []string{lower, upper, digits, symbols}, nil},
		{"no symbols", Policy{Length: 20, NoSymbols: true}, []string{lower, upper, digits}, []string{symbols}},
		{"lower only", Policy{Length: 12, NoUpper: true, NoDigits: true, NoSymbols: true}, []string{lower}, []string{upper, digits, symbols}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for range 50 {
				got, err := Password(tt.policy)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != tt.policy.Length {
					t.Fatalf("length %d", len(got))
				}
				for _, class := range tt.want {
					if !strings.ContainsAny(got, class) {
						t.Fatalf("%q lacks a character of %q", got, class)
					}
				}
				for _, class := range tt.absent {
					if strings.ContainsAny(got, class) {
						t.Fatalf("%q contains a disabled class %q", got, class)
					}
				}
			}
		})
	}
}

func TestPasswordRejectsBadLength(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, MinLength - 1, MaxLength + 1} {
		if _, err := Password(Policy{Length: n}); !errors.Is(err, ErrPolicy) {
			t.Fatalf("length %d accepted: %v", n, err)
		}
	}
}
