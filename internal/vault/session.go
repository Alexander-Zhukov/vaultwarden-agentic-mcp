package vault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

// Credentials unlock one account without a human: the personal API key logs
// in, the master password derives the keys that decrypt the vault. The secret
// halves stay config.Secret until the moment they are sent or derived from.
type Credentials struct {
	ClientID     string
	ClientSecret config.Secret
	Password     config.Secret
}

// ErrLoginBackoff is returned while the session waits out a failed login
// instead of hammering the server's rate limiter.
var ErrLoginBackoff = errors.New("login is backing off after a failure")

// session owns the access token and the account's unwrapped keys. Tokens from
// an API-key login carry no refresh token, so renewal is a fresh login. The
// keys are derived again whenever the server hands out different encrypted
// keys, which is what an account key rotation looks like from here.
type session struct {
	client *bitwarden.Client
	creds  Credentials
	device bitwarden.Device
	now    func() time.Time

	mu        sync.Mutex
	token     string
	issuedAt  time.Time
	expiresAt time.Time
	email     string
	userKey   keys.SymmetricKey
	private   keys.PrivateKey
	// unlockedFrom is the encrypted material the keys were derived from.
	unlockedFrom string
	failures     int
	retryAt      time.Time
	onLogin      func(err error)
	// margin is how long before expiry a token is replaced, so a request
	// never leaves with a token that dies in flight.
	margin     time.Duration
	backoffMin time.Duration
	backoffMax time.Duration
}

// deviceFor derives a stable device identifier from the client ID, so every
// restart presents itself as the same device and the account's device list
// does not grow by one per deployment.
func deviceFor(clientID, name string) bitwarden.Device {
	sum := sha256.Sum256([]byte("vaultwarden-mcp device " + clientID))
	sum[6] = (sum[6] & 0x0f) | 0x40 // version 4 layout
	sum[8] = (sum[8] & 0x3f) | 0x80 // RFC 4122 variant
	id := fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
	return bitwarden.Device{Identifier: id, Name: name}
}

// Token returns a valid access token, logging in when there is none or it is
// about to expire.
func (s *session) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Add(s.margin).Before(s.expiresAt) {
		return s.token, nil
	}
	if err := s.loginLocked(ctx); err != nil {
		return "", err
	}
	return s.token, nil
}

// Invalidate drops the token after the server rejected a request sent at
// the given moment. A token obtained since then is newer than the rejected
// one and is kept, so concurrent failures do not force a login each.
func (s *session) Invalidate(sentAt time.Time) {
	s.mu.Lock()
	if !s.issuedAt.After(sentAt) {
		s.token = ""
	}
	s.mu.Unlock()
}

// Keys returns the account's unwrapped keys, logging in first if needed.
func (s *session) Keys(ctx context.Context) (keys.SymmetricKey, keys.PrivateKey, string, error) {
	if _, err := s.Token(ctx); err != nil {
		return keys.SymmetricKey{}, keys.PrivateKey{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userKey, s.private, s.email, nil
}

func (s *session) loginLocked(ctx context.Context) (err error) {
	if now := s.now(); now.Before(s.retryAt) {
		return fmt.Errorf("%w; next attempt in %s", ErrLoginBackoff, s.retryAt.Sub(now).Round(time.Second))
	}
	defer func() {
		if s.onLogin != nil {
			s.onLogin(err)
		}
		// A caller that gave up is not the server refusing: backing off for
		// it would stall every other caller.
		if err != nil && ctx.Err() == nil {
			s.failures++
			s.retryAt = s.now().Add(backoff(s.failures, s.backoffMin, s.backoffMax))
			return
		}
		if err != nil {
			return
		}
		s.failures = 0
		s.retryAt = time.Time{}
	}()

	resp, err := s.client.LoginAPIKey(ctx, s.creds.ClientID, s.creds.ClientSecret.Reveal(), s.device)
	if err != nil {
		return fmt.Errorf("log in: %w", err)
	}
	if resp.AccessToken == "" || resp.Key == "" || resp.PrivateKey == "" {
		return errors.New("log in: server answered without a token or account keys")
	}
	email := salt(resp)
	if email == "" {
		return errors.New("log in: cannot determine the account email from the token")
	}
	material := email + "\x00" + resp.Key + "\x00" + resp.PrivateKey
	if s.userKey.IsZero() || material != s.unlockedFrom {
		if err := s.unlock(resp, email); err != nil {
			return err
		}
		s.unlockedFrom = material
	}
	s.token = resp.AccessToken
	s.issuedAt = s.now()
	s.expiresAt = s.now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	return nil
}

// unlock derives the master key and unwraps the user and private keys.
func (s *session) unlock(resp *bitwarden.TokenResponse, email string) error {
	kdf := keys.KDF{Type: keys.KDFType(resp.Kdf), Iterations: resp.KdfIterations}
	if resp.KdfMemory != nil {
		kdf.Memory = *resp.KdfMemory
	}
	if resp.KdfParallelism != nil {
		kdf.Parallelism = *resp.KdfParallelism
	}
	master, err := keys.MasterKey(s.creds.Password.Reveal(), email, kdf)
	if err != nil {
		return fmt.Errorf("derive master key: %w", err)
	}
	stretched, err := keys.StretchMasterKey(master)
	if err != nil {
		return err
	}
	userKey, err := stretched.DecryptKey(resp.Key)
	if err != nil {
		// A MAC failure here is what a wrong master password looks like.
		return fmt.Errorf("unlock vault (wrong master password?): %w", err)
	}
	encPrivate, err := keys.ParseEncString(resp.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	der, err := userKey.Decrypt(encPrivate)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}
	private, err := keys.ParsePrivateKey(der)
	if err != nil {
		return err
	}
	s.email, s.userKey, s.private = email, userKey, private
	return nil
}

// salt finds the account email the master key is salted with: servers that
// report it directly do so in the decryption options, older ones only inside
// the access token.
func salt(resp *bitwarden.TokenResponse) string {
	if o := resp.UserDecryptionOptions; o != nil && o.MasterPasswordUnlock != nil && o.MasterPasswordUnlock.Salt != "" {
		return o.MasterPasswordUnlock.Salt
	}
	parts := strings.Split(resp.AccessToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Email
}

// backoff doubles from lo with every failure, up to hi.
func backoff(failures int, lo, hi time.Duration) time.Duration {
	d := lo
	for i := 1; i < failures && d < hi; i++ {
		d *= 2
	}
	return min(d, hi)
}
