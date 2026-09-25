//go:build integration

// Package vwtest provisions throwaway accounts and organizations on a real
// Vaultwarden instance for integration tests. It does client-side what the web
// vault does on sign-up, so tests start from an account no human touched.
package vwtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

// URLEnv names the variable pointing at the test server.
const URLEnv = "VWTEST_URL"

// Account is a provisioned account with everything a test needs to log in.
type Account struct {
	Email        string
	Password     string
	UserID       string
	ClientID     string
	ClientSecret string
	UserKey      keys.SymmetricKey
	Private      keys.PrivateKey
	Client       *bitwarden.Client
}

// Organization is a provisioned organization with its default collection.
type Organization struct {
	ID           string
	Key          keys.SymmetricKey
	CollectionID string
}

// ServerURL returns the test server, skipping the test when none is set.
func ServerURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv(URLEnv)
	if u == "" {
		t.Skipf("%s is not set", URLEnv)
	}
	return u
}

// token holds the access token of a test account for its client.
type token struct{ value string }

func (tk *token) get(context.Context) (string, error) { return tk.value, nil }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails since Go 1.24: it crashes the process instead
	return hex.EncodeToString(b)
}

// NewAccount registers an account with a PBKDF2 KDF, logs it in and fetches its
// API key.
func NewAccount(ctx context.Context, t *testing.T, prefix string) *Account {
	t.Helper()
	server := ServerURL(t)
	tk := &token{}
	client, err := bitwarden.New(bitwarden.Config{
		BaseURL: server, Timeout: 30 * time.Second, MaxResponseBytes: 32 << 20, Token: tk.get,
	})
	if err != nil {
		t.Fatal(err)
	}

	email := fmt.Sprintf("%s-%s@example.test", prefix, randomHex(4))
	password := "pw-" + randomHex(8)
	kdf := keys.KDF{Type: keys.KDFPBKDF2, Iterations: 600000}
	master, err := keys.MasterKey(password, email, kdf)
	if err != nil {
		t.Fatal(err)
	}
	stretched, err := keys.StretchMasterKey(master)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := keys.MasterPasswordHash(master, password)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := keys.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	wrappedUserKey, err := stretched.EncryptKey(userKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := keys.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := private.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	encPrivate, err := userKey.Encrypt(der)
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicSPKI()
	if err != nil {
		t.Fatal(err)
	}

	err = client.Register(ctx, bitwarden.Registration{
		Email: email, Name: prefix, MasterPasswordHash: hash, Key: wrappedUserKey,
		Kdf: int(kdf.Type), KdfIterations: kdf.Iterations,
		Keys: bitwarden.RegistrationKeyPair{PublicKey: public, EncryptedPrivateKey: encPrivate.String()},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	dev := bitwarden.Device{Identifier: "00000000-0000-4000-8000-" + randomHex(6), Name: "vwtest"}
	resp, err := client.LoginPassword(ctx, email, hash, dev)
	if err != nil {
		t.Fatalf("password login: %v", err)
	}
	tk.value = resp.AccessToken
	secret, err := client.APIKey(ctx, hash)
	if err != nil {
		t.Fatalf("api key: %v", err)
	}
	sync, err := client.Sync(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	return &Account{
		Email: email, Password: password, UserID: sync.Profile.ID,
		ClientID: "user." + sync.Profile.ID, ClientSecret: secret,
		UserKey: userKey, Private: private, Client: client,
	}
}

// NewOrganization creates an organization owned by the account, with one
// collection named after the argument.
func (a *Account) NewOrganization(ctx context.Context, t *testing.T, name, collection string) *Organization {
	t.Helper()
	orgKey, err := keys.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := a.Private.Public().EncryptKey(orgKey)
	if err != nil {
		t.Fatal(err)
	}
	orgPrivate, err := keys.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := orgPrivate.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	encPrivate, err := orgKey.Encrypt(der)
	if err != nil {
		t.Fatal(err)
	}
	public, err := orgPrivate.PublicSPKI()
	if err != nil {
		t.Fatal(err)
	}
	collName, err := orgKey.EncryptString(collection)
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.Client.CreateOrganization(ctx, bitwarden.OrganizationRequest{
		Name: name, BillingEmail: a.Email, PlanType: 0, Key: wrapped,
		Keys:           bitwarden.RegistrationKeyPair{PublicKey: public, EncryptedPrivateKey: encPrivate.String()},
		CollectionName: collName,
	})
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	sync, err := a.Client.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	org := &Organization{ID: id, Key: orgKey}
	for _, c := range sync.Collections {
		if strings.EqualFold(c.OrganizationID, id) {
			org.CollectionID = c.ID
		}
	}
	if org.CollectionID == "" {
		t.Fatal("organization has no default collection")
	}
	return org
}
