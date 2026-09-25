package mcpserver

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

// secrets are planted in every field that must never leave through a view.
var secrets = []string{"PW-SECRET", "TOTP-SEED", "HIDDEN-VALUE", "SSH-PRIVATE", "4111111111114444", "CVV-999", "SSN-123", "NOTE-SECRET", "OLD-PW"}

func leakyItem() vault.Item {
	return vault.Item{
		ID: "i1", Name: "everything", Type: vault.TypeLogin, Notes: "Description: fine to show",
		Username: "bot", Password: "PW-SECRET", TOTP: "TOTP-SEED",
		Fields:          []vault.Field{{Name: "hidden", Value: "HIDDEN-VALUE", Kind: vault.FieldHidden}, {Name: "region", Value: "eu", Kind: vault.FieldText}},
		SSH:             &vault.SSHKey{Private: "SSH-PRIVATE", Public: "ssh-ed25519 AAA", Fingerprint: "SHA256:x"},
		Card:            map[string]string{"number": "4111111111114444", "code": "CVV-999", "brand": "visa"},
		Identity:        map[string]string{"ssn": "SSN-123", "first_name": "Ann"},
		PasswordHistory: []vault.PasswordChange{{Password: "OLD-PW", Changed: time.Unix(0, 0)}},
	}
}

func testConfig() *config.Config {
	return &config.Config{Location: time.UTC, Checks: config.Checks{ExpiryField: "expires"}}
}

func TestViewsNeverCarrySecrets(t *testing.T) {
	t.Parallel()
	snap := &vault.Snapshot{}
	it := leakyItem()
	note := vault.Item{ID: "n1", Name: "note", Type: vault.TypeNote, Notes: "NOTE-SECRET"}
	for _, view := range []any{summarize(snap, &it, testConfig()), detail(snap, &it, testConfig()), detail(snap, &note, testConfig())} {
		data, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if strings.Contains(string(data), s) {
				t.Fatalf("view leaks %q: %s", s, data)
			}
		}
	}
	d := detail(snap, &it, testConfig())
	if d.Card["number_last4"] != "4444" || d.Notes == "" || d.SSHPublicKey == "" || d.Identity["first_name"] != "Ann" {
		t.Fatalf("view drops metadata: %+v", d)
	}
	if len(d.Fields) != 2 || d.Fields[0].Value != "" || d.Fields[1].Value != "eu" {
		t.Fatalf("fields %+v", d.Fields)
	}
}

func TestValueOf(t *testing.T) {
	t.Parallel()
	it := leakyItem()
	it.Viewable = true
	it.TOTP = "otpauth://totp/x?secret=" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890")) + "&digits=8"
	code, validFor, err := valueOf(&it, "totp", time.Unix(59, 0))
	if err != nil || code != "94287082" || validFor != time.Second {
		t.Fatalf("totp %q %s %v", code, validFor, err)
	}
	if v, _, err := valueOf(&it, "", time.Now()); err != nil || v != "PW-SECRET" {
		t.Fatalf("default field %q %v", v, err)
	}
	if _, _, err := valueOf(&it, "field:nope", time.Now()); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("missing field %v", err)
	}
	it.Viewable = false
	if _, _, err := valueOf(&it, "password", time.Now()); !errors.Is(err, vault.ErrReadOnly) {
		t.Fatalf("hidden passwords must not be revealed: %v", err)
	}
	if v, _, err := valueOf(&it, "username", time.Now()); err != nil || v != "bot" {
		t.Fatalf("non-secret values stay readable: %q %v", v, err)
	}
}

func TestUploadTargets(t *testing.T) {
	t.Parallel()
	login := &vault.Item{Name: "l", Type: vault.TypeLogin}
	ssh := &vault.Item{Name: "s", Type: vault.TypeSSHKey}
	tests := []struct {
		it    *vault.Item
		field string
		ok    bool
	}{
		{login, "password", true},
		{login, "totp", true},
		{login, "notes", false},
		{&vault.Item{Name: "n", Type: vault.TypeNote}, "notes", true},
		{login, "field:api", true},
		{login, "ssh_private_key", false},
		{ssh, "password", false},
		{ssh, "ssh_private_key", true},
		{login, "field:", false},
		{login, "username", false},
	}
	for _, tt := range tests {
		if err := uploadableField(tt.it, tt.field); (err == nil) != tt.ok {
			t.Fatalf("%s/%s: %v", tt.it.Type, tt.field, err)
		}
	}
	it := &vault.Item{Fields: []vault.Field{{Name: "api", Value: "old", Kind: vault.FieldText}}}
	for field, value := range map[string]string{"password": "p", "totp": "t", "notes": "n", "ssh_private_key": "k", "field:api": "new", "field:extra": "e"} {
		if err := storeField(it, field, value); err != nil {
			t.Fatal(err)
		}
	}
	// An uploaded value lands hidden even in a field that was text.
	if it.Password != "p" || it.SSH.Private != "k" || it.Fields[0].Value != "new" || it.Fields[0].Kind != vault.FieldHidden || it.Fields[1].Kind != vault.FieldHidden {
		t.Fatalf("stored %+v", it)
	}
}

func TestClampTTL(t *testing.T) {
	t.Parallel()
	if d, err := clampTTL("", time.Minute, 5*time.Minute); err != nil || d != time.Minute {
		t.Fatalf("%s %v", d, err)
	}
	if d, err := clampTTL("1h", time.Minute, 5*time.Minute); err != nil || d != 5*time.Minute {
		t.Fatalf("%s %v", d, err)
	}
	for _, bad := range []string{"-1m", "soon", "0s"} {
		if _, err := clampTTL(bad, time.Minute, time.Hour); !errors.Is(err, vault.ErrInvalid) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestReadUpload(t *testing.T) {
	t.Parallel()
	var mp bytes.Buffer
	w := multipart.NewWriter(&mp)
	part, _ := w.CreateFormFile("file", "id_ed25519")
	_, _ = part.Write([]byte("FILE"))
	_ = w.Close()
	tests := []struct {
		name   string
		ctype  string
		body   string
		file   bool
		want   string
		err    bool
		method string
	}{
		{"raw", "", "raw-value", false, "raw-value", false, ""},
		{"form", "application/x-www-form-urlencoded", "value=form+value", false, "form value", false, ""},
		{"multipart", w.FormDataContentType(), mp.String(), true, "FILE", false, ""},
		{"too large", "", strings.Repeat("x", 20), false, "", true, ""},
		{"file via urlencoded", "application/x-www-form-urlencoded", "value=x", true, "", true, ""},
		// curl --data-binary @- sends this type with a raw body.
		{"put labelled as a form", "application/x-www-form-urlencoded", "raw=value&x", false, "raw=value&x", false, http.MethodPut},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "/v1/upload/x", strings.NewReader(tt.body))
			if tt.ctype != "" {
				req.Header.Set("Content-Type", tt.ctype)
			}
			got, err := readUpload(httptest.NewRecorder(), req, 16, tt.file)
			if (err != nil) != tt.err || (err == nil && string(got) != tt.want) {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestLinkEndpointsRefuseUnknownTokens(t *testing.T) {
	t.Parallel()
	srv := LinkHandlers(Deps{Config: testConfig(), Links: newStore(), Metrics: newMetrics(), Logger: discard(), Clock: time.Now})
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/links/nope", nil),
		httptest.NewRequest(http.MethodGet, "/v1/upload/nope", nil),
		httptest.NewRequest(http.MethodPut, "/v1/upload/nope", strings.NewReader("x")),
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusGone || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: %d %v", req.Method, req.URL.Path, rec.Code, rec.Header())
		}
	}
}
