package mcpserver

import (
	"log/slog"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/links"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/obs"
)

func newStore() *links.Store   { return links.NewStore(time.Now, 64) }
func newMetrics() *obs.Metrics { return obs.NewMetrics() }
func discard() *slog.Logger    { return slog.New(slog.DiscardHandler) }
