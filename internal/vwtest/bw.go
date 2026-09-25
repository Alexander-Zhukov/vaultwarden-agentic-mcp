//go:build integration

package vwtest

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// BWImageEnv names the image with the official CLI; `make test-integration`
// builds it from test/bw.
const BWImageEnv = "VWTEST_BW_IMAGE"

// BW runs a shell script inside the official Bitwarden CLI image, logged in and
// unlocked as the account. The script sees the session in $S, so a command is
// written as `bw get item NAME --session "$S"`. It returns stdout.
func (a *Account) BW(ctx context.Context, t *testing.T, script string) string {
	t.Helper()
	image := os.Getenv(BWImageEnv)
	if image == "" {
		t.Skipf("%s is not set", BWImageEnv)
	}
	prelude := `set -e
bw config server "$VW_URL" >/dev/null
bw login --apikey >/dev/null
S=$(bw unlock --raw --passwordenv BW_PASSWORD)
bw sync --session "$S" >/dev/null
`
	ca := os.Getenv("VWTEST_CA")
	if ca == "" {
		t.Skip("VWTEST_CA is not set")
	}
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--network", "host",
		"-v", ca+":/ca.crt:ro",
		"-e", "NODE_EXTRA_CA_CERTS=/ca.crt",
		"-e", "VW_URL="+ServerURL(t),
		"-e", "BW_CLIENTID="+a.ClientID,
		"-e", "BW_CLIENTSECRET="+a.ClientSecret,
		"-e", "BW_PASSWORD="+a.Password,
		"--entrypoint", "sh", image)
	cmd.Stdin = strings.NewReader(prelude + script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("bw script failed: %v\n%s", err, stderr.String())
	}
	return stdout.String()
}
