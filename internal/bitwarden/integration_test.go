//go:build integration

package bitwarden_test

import (
	"context"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vwtest"
)

func ptr[T any](v T) *T { return &v }

// TestLiveProtocol walks the whole protocol once against a real server: an
// account logs in with its API key, unwraps its keys from the token response,
// and round-trips an organization item.
func TestLiveProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	acct := vwtest.NewAccount(ctx, t, "proto")
	org := acct.NewOrganization(ctx, t, "Proto Org", "infra")

	var token string
	client, err := bitwarden.New(bitwarden.Config{
		BaseURL: vwtest.ServerURL(t), Timeout: 30 * time.Second, MaxResponseBytes: 32 << 20,
		Token: func(context.Context) (string, error) { return token, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.LoginAPIKey(ctx, acct.ClientID, acct.ClientSecret,
		bitwarden.Device{Identifier: "11111111-2222-4333-8444-555555555555", Name: "proto"})
	if err != nil {
		t.Fatalf("api key login: %v", err)
	}
	token = resp.AccessToken
	t.Logf("kdf=%d iterations=%d has_key=%v has_private=%v expires_in=%d",
		resp.Kdf, resp.KdfIterations, resp.Key != "", resp.PrivateKey != "", resp.ExpiresIn)

	master, err := keys.MasterKey(acct.Password, acct.Email, keys.KDF{Type: keys.KDFType(resp.Kdf), Iterations: resp.KdfIterations})
	if err != nil {
		t.Fatal(err)
	}
	stretched, err := keys.StretchMasterKey(master)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := stretched.DecryptKey(resp.Key)
	if err != nil {
		t.Fatalf("unwrap user key: %v", err)
	}
	encPriv, err := keys.ParseEncString(resp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := userKey.Decrypt(encPriv)
	if err != nil {
		t.Fatalf("decrypt private key: %v", err)
	}
	private, err := keys.ParsePrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}

	sync, err := client.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var orgKey keys.SymmetricKey
	for _, o := range sync.Profile.Organizations {
		if o.ID == org.ID {
			orgKey, err = private.DecryptKey(o.Key)
			if err != nil {
				t.Fatalf("unwrap org key: %v", err)
			}
		}
	}
	if orgKey.IsZero() {
		t.Fatal("organization missing from sync")
	}

	enc := func(s string) *string {
		v, err := orgKey.EncryptString(s)
		if err != nil {
			t.Fatal(err)
		}
		return &v
	}
	created, err := client.CreateCipher(ctx, bitwarden.Cipher{
		OrganizationID: ptr(org.ID),
		Type:           bitwarden.CipherLogin,
		Name:           *enc("PROTO_ITEM"),
		Notes:          enc("Description: test"),
		Login:          &bitwarden.Login{Username: enc("bot"), Password: enc("s3cret")},
		Fields:         []bitwarden.Field{{Name: enc("expires"), Value: enc("2027-01-01"), Type: bitwarden.FieldText}},
	}, []string{org.CollectionID})
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}

	sync, err = client.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range sync.Ciphers {
		if c.ID != created.ID {
			continue
		}
		name, err := orgKey.DecryptString(c.Name)
		if err != nil || name != "PROTO_ITEM" {
			t.Fatalf("name %q, %v", name, err)
		}
		pass, err := orgKey.DecryptString(*c.Login.Password)
		if err != nil || pass != "s3cret" {
			t.Fatalf("password %q, %v", pass, err)
		}
		if len(c.CollectionIDs) != 1 || c.CollectionIDs[0] != org.CollectionID {
			t.Fatalf("collections %v", c.CollectionIDs)
		}
	}

	// What this client wrote must read back in the official CLI.
	got := acct.BW(ctx, t, `bw get password PROTO_ITEM --session "$S"`)
	if got != "s3cret" {
		t.Fatalf("bw read password %q", got)
	}

	// And what the official CLI writes must decrypt here, including the
	// per-item key current clients add.
	item := `{"organizationId":"` + org.ID + `","collectionIds":["` + org.CollectionID + `"],` +
		`"type":1,"name":"FROM_BW","notes":"n","login":{"username":"u","password":"from-bw"}}`
	acct.BW(ctx, t, `echo '`+item+`' | bw encode | bw create item --organizationid `+org.ID+` --session "$S" >/dev/null`)
	sync, err = client.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range sync.Ciphers {
		name, err := orgKey.DecryptString(c.Name)
		itemKey := orgKey
		if c.Key != nil {
			itemKey, err = orgKey.DecryptKey(*c.Key)
			if err != nil {
				t.Fatalf("unwrap item key: %v", err)
			}
			name, err = itemKey.DecryptString(c.Name)
		}
		if err != nil {
			t.Fatalf("decrypt name of %s: %v", c.ID, err)
		}
		if name != "FROM_BW" {
			continue
		}
		t.Logf("bw item has per-item key: %v", c.Key != nil)
		pass, err := itemKey.DecryptString(*c.Login.Password)
		if err != nil || pass != "from-bw" {
			t.Fatalf("bw password %q, %v", pass, err)
		}
		return
	}
	t.Fatal("item created by bw missing from sync")
}
