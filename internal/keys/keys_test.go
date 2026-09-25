package keys

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func mustKey(t *testing.T) SymmetricKey {
	t.Helper()
	k, err := GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSymmetricRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		plain []byte
	}{
		{"empty", nil},
		{"one byte", []byte("x")},
		{"exact block", bytes.Repeat([]byte("a"), 16)},
		{"multi block", bytes.Repeat([]byte("секрет"), 50)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k := mustKey(t)
			enc, err := k.Encrypt(tt.plain)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseEncString(enc.String())
			if err != nil {
				t.Fatal(err)
			}
			got, err := k.Decrypt(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.plain) {
				t.Fatalf("got %q, want %q", got, tt.plain)
			}
		})
	}
}

func TestDecryptRejectsTamperingAndForeignKeys(t *testing.T) {
	t.Parallel()
	k := mustKey(t)
	enc, err := k.Encrypt([]byte("value"))
	if err != nil {
		t.Fatal(err)
	}

	flipped := enc
	flipped.Data = bytes.Clone(enc.Data)
	flipped.Data[0] ^= 1

	tests := []struct {
		name string
		key  SymmetricKey
		enc  EncString
		want error
	}{
		{"tampered data", k, flipped, ErrMAC},
		{"foreign key", mustKey(t), enc, ErrMAC},
		{"rsa type", k, EncString{Type: RSA2048OAEPSHA1, Data: []byte{1}}, ErrUnsupported},
		{"zero key", SymmetricKey{}, enc, ErrKeySize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tt.key.Decrypt(tt.enc); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestBufferRoundTrip(t *testing.T) {
	t.Parallel()
	k := mustKey(t)
	plain := bytes.Repeat([]byte{0, 1, 2, 250}, 1000)
	buf, err := k.EncryptBuffer(plain)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != byte(AESCBC256HMACSHA256) {
		t.Fatalf("type byte %d", buf[0])
	}
	got, err := k.DecryptBuffer(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("buffer mismatch")
	}
	if _, err := k.DecryptBuffer(buf[:20]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short buffer: %v", err)
	}
}

func TestKeyWrapping(t *testing.T) {
	t.Parallel()
	outer, inner := mustKey(t), mustKey(t)
	wrapped, err := outer.EncryptKey(inner)
	if err != nil {
		t.Fatal(err)
	}
	got, err := outer.DecryptKey(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), inner.Bytes()) {
		t.Fatal("unwrapped key differs")
	}
}

func TestParseEncString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want EncType
		err  error
	}{
		{"type 2", "2.AAAA|AAAA|AAAA", AESCBC256HMACSHA256, nil},
		{"legacy three parts", "AAAA|AAAA|AAAA", AESCBC128HMACSHA256, nil},
		{"legacy two parts", "AAAA|AAAA", AESCBC256, nil},
		{"rsa", "4.AAAA", RSA2048OAEPSHA1, nil},
		{"rsa with mac", "6.AAAA|AAAA", RSA2048OAEPSHA1HMACSHA256, nil},
		{"empty", "", 0, ErrMalformed},
		{"bad header", "x.AAAA", 0, ErrMalformed},
		{"unknown type", "9.AAAA", 0, ErrUnsupported},
		{"wrong part count", "2.AAAA|AAAA", 0, ErrMalformed},
		{"bad base64", "2.!!|AAAA|AAAA", 0, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseEncString(tt.in)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err %v, want %v", err, tt.err)
			}
			if err == nil && got.Type != tt.want {
				t.Fatalf("type %d, want %d", got.Type, tt.want)
			}
		})
	}
}

func FuzzParseEncString(f *testing.F) {
	for _, seed := range []string{"2.AAAA|AAAA|AAAA", "4.AAAA", "AAAA|AAAA", "0.a|b", "6.|", "..|"} {
		f.Add(seed)
	}
	k, err := GenerateSymmetricKey()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, in string) {
		enc, err := ParseEncString(in)
		if err != nil {
			return
		}
		// Whatever parses must never make decryption panic.
		_, _ = k.Decrypt(enc)
		if !enc.Type.isRSA() && enc.Type != AESCBC256 && !strings.Contains(enc.String(), "|") {
			t.Fatalf("rendered symmetric value without parts: %q", enc.String())
		}
	})
}

func TestMasterKeyDerivation(t *testing.T) {
	t.Parallel()
	pbkdf := KDF{Type: KDFPBKDF2, Iterations: 600000}
	argon := KDF{Type: KDFArgon2id, Iterations: 3, Memory: 64, Parallelism: 4}

	a, err := MasterKey("pass", " User@Example.com ", pbkdf)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MasterKey("pass", "user@example.com", pbkdf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("email is not normalised before salting")
	}
	c, err := MasterKey("pass", "user@example.com", argon)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) || len(c) != 32 {
		t.Fatal("argon2id key must differ from pbkdf2 and be 32 bytes")
	}

	for _, weak := range []KDF{
		{Type: KDFPBKDF2, Iterations: 1},
		{Type: KDFArgon2id, Iterations: 1, Memory: 64, Parallelism: 4},
		{Type: KDFArgon2id, Iterations: 3, Memory: 1, Parallelism: 4},
		{Type: 7, Iterations: 600000},
	} {
		if _, err := MasterKey("pass", "user@example.com", weak); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("weak kdf %+v accepted: %v", weak, err)
		}
	}
}

func TestRSAWrapping(t *testing.T) {
	t.Parallel()
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	spki, err := priv.PublicSPKI()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	orgKey := mustKey(t)
	wrapped, err := pub.EncryptKey(orgKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(wrapped, "4.") {
		t.Fatalf("wrapped key %q is not type 4", wrapped[:2])
	}
	got, err := priv.DecryptKey(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), orgKey.Bytes()) {
		t.Fatal("org key differs after unwrap")
	}

	der, err := priv.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParsePrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.DecryptKey(wrapped); err != nil {
		t.Fatalf("reparsed key cannot unwrap: %v", err)
	}
	if phrase, err := pub.FingerprintPhrase("u"); err != nil || phrase == "" {
		t.Fatalf("phrase %q, %v", phrase, err)
	}
}

func TestSendKeyIsDeterministic(t *testing.T) {
	t.Parallel()
	seed := bytes.Repeat([]byte{7}, 16)
	a, err := SendKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SendKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("send key must depend only on the seed")
	}
}

// TestStrippedMACIsRefused covers the downgrade a hostile server could try:
// the same ciphertext relabelled as type 0 must not decrypt.
func TestStrippedMACIsRefused(t *testing.T) {
	t.Parallel()
	k := mustKey(t)
	enc, err := k.Encrypt([]byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		EncString{Type: AESCBC256, IV: enc.IV, Data: enc.Data}.String(),
		strings.TrimPrefix(enc.String(), "2."),
	} {
		parsed, err := ParseEncString(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := k.Decrypt(parsed); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%q decrypted without its MAC: %v", s[:4], err)
		}
	}
}

func TestFingerprintPhrase(t *testing.T) {
	t.Parallel()
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	a, err := pub.FingerprintPhrase("user-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pub.FingerprintPhrase("user-1")
	c, _ := pub.FingerprintPhrase("user-2")
	if a != b || a == c || strings.Count(a, "-") != phraseWords-1 {
		t.Fatalf("phrases %q %q %q", a, b, c)
	}
	if n := len(strings.Split(strings.TrimSpace(wordlist), "\n")); n != 7776 {
		t.Fatalf("word list has %d words", n)
	}
}
