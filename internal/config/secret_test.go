package config_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

const password = "correct-horse-battery-staple"

func TestSecretNeverLeaksThroughFormatting(t *testing.T) {
	t.Parallel()
	secret := config.Secret(password)
	holder := struct{ Password config.Secret }{Password: secret}

	cases := []struct {
		name  string
		verb  string
		value any
	}{
		{name: "verb v", verb: "%v", value: secret},
		{name: "verb s", verb: "%s", value: secret},
		{name: "verb q", verb: "%q", value: secret},
		{name: "struct plus v", verb: "%+v", value: holder},
		{name: "struct sharp v", verb: "%#v", value: holder},
	}

	if got := secret.String(); strings.Contains(got, password) {
		t.Errorf("String() leaked the secret: %s", got)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rendered := fmt.Sprintf(tc.verb, tc.value)
			if strings.Contains(rendered, password) {
				t.Errorf("rendering with %s leaked the secret: %s", tc.verb, rendered)
			}
		})
	}
}

func TestSecretNeverLeaksThroughJSON(t *testing.T) {
	t.Parallel()
	holder := struct {
		Password config.Secret `json:"password"`
	}{Password: config.Secret(password)}

	encoded, err := json.Marshal(holder)
	if err != nil {
		t.Fatalf("Marshal() returned error: %v", err)
	}
	if strings.Contains(string(encoded), password) {
		t.Errorf("JSON encoding leaked the secret: %s", encoded)
	}
}

func TestSecretRevealReturnsValue(t *testing.T) {
	t.Parallel()
	if got := config.Secret(password).Reveal(); got != password {
		t.Errorf("Reveal() = %q, want %q", got, password)
	}
}
