package totp

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B: the reference secrets per algorithm and the expected
// eight-digit codes.
func TestRFC6238Vectors(t *testing.T) {
	t.Parallel()
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	sha1Key := enc.EncodeToString([]byte("12345678901234567890"))
	sha256Key := enc.EncodeToString([]byte("12345678901234567890123456789012"))
	sha512Key := enc.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	tests := []struct {
		name string
		seed string
		at   int64
		want string
	}{
		{"sha1 59", "otpauth://totp/x?secret=" + sha1Key + "&digits=8", 59, "94287082"},
		{"sha1 1111111109", "otpauth://totp/x?secret=" + sha1Key + "&digits=8", 1111111109, "07081804"},
		{"sha256 59", "otpauth://totp/x?secret=" + sha256Key + "&digits=8&algorithm=SHA256", 59, "46119246"},
		{"sha512 59", "otpauth://totp/x?secret=" + sha512Key + "&digits=8&algorithm=SHA512", 59, "90693936"},
		{"sha1 2000000000", "otpauth://totp/x?secret=" + sha1Key + "&digits=8", 2000000000, "69279037"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := Parse(tt.seed)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.At(time.Unix(tt.at, 0)).Code; got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBareSecretAndExpiry(t *testing.T) {
	t.Parallel()
	p, err := Parse("gezd gnbv gy3t qojq")
	if err != nil {
		t.Fatal(err)
	}
	c := p.At(time.Unix(65, 0))
	if len(c.Code) != 6 || c.ExpiresIn != 25*time.Second || c.Period != 30*time.Second {
		t.Fatalf("unexpected %+v", c)
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	for _, seed := range []string{"", "not base32 !!", "otpauth://totp/x?secret=GEZDGNBV&digits=3", "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5"} {
		if _, err := Parse(seed); !errors.Is(err, ErrSeed) {
			t.Fatalf("%q accepted: %v", seed, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"GEZDGNBV", "otpauth://totp/x?secret=GEZDGNBV&digits=8&period=60&algorithm=SHA512",
		"steam://GEZDGNBV", "otpauth://%zz", "otpauth://totp/x?secret=&digits=99",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed string) {
		p, err := Parse(seed)
		if err != nil {
			// A parse error never quotes the seed back.
			if len(seed) > 12 && strings.Contains(err.Error(), seed) {
				t.Fatalf("error quotes the seed: %v", err)
			}
			return
		}
		c := p.At(time.Unix(1_800_000_000, 0))
		if c.Code == "" || c.ExpiresIn <= 0 || c.ExpiresIn > c.Period {
			t.Fatalf("bad code %+v for %q", c, seed)
		}
	})
}

func TestTenDigits(t *testing.T) {
	t.Parallel()
	p, err := Parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=10")
	if err != nil {
		t.Fatal(err)
	}
	if code := p.At(time.Unix(59, 0)).Code; len(code) != 10 {
		t.Fatalf("code %q", code)
	}
}
