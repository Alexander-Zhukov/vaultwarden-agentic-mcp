package mcpserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/config"
)

// TestEveryToolIsClassified checks that no tool of any mode falls through to
// the fallback annotations, which tell clients "destructive, reaches the world"
// for lack of knowing better.
func TestEveryToolIsClassified(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	consumer, _, _ := fakeHarness(t, config.ModeConsumer, true)
	admin, _, _ := fakeHarness(t, config.ModeAdmin, true)
	server, _ := serverHarness(t, false, true)
	seen := 0
	for _, h := range []*harness{consumer, admin, server} {
		tools, err := h.session(ctx, "op").ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range tools.Tools {
			if fallback(tool.Annotations) {
				t.Errorf("%s has no class in toolClasses", tool.Name)
			}
			seen++
		}
	}
	if seen < 40 {
		t.Fatalf("only %d tools listed", seen)
	}
}

func fallback(a *mcp.ToolAnnotations) bool {
	return a == nil || !a.ReadOnlyHint && a.DestructiveHint != nil && *a.DestructiveHint && a.OpenWorldHint != nil && *a.OpenWorldHint
}
