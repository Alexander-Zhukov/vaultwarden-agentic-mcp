package obs

import (
	"net/http"
	"sync/atomic"
)

// Readiness separates "the process is alive" from "the vault is unlocked and synced and
// traffic can be served". Liveness must never depend on an external system:
// a Vaultwarden outage should not make an orchestrator kill a healthy process.
type Readiness struct {
	ready atomic.Bool
}

// NewReadiness returns a gate that starts closed.
func NewReadiness() *Readiness { return &Readiness{} }

// Set opens or closes the gate.
func (r *Readiness) Set(ready bool) { r.ready.Store(ready) }

// Ready reports the current state.
func (r *Readiness) Ready() bool { return r.ready.Load() }

// LivenessHandler answers as long as the process can serve HTTP at all.
func LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writePlain(w, http.StatusOK, "ok")
	})
}

// ReadinessHandler answers 200 only once dependencies are usable.
func (r *Readiness) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !r.Ready() {
			writePlain(w, http.StatusServiceUnavailable, "not ready")
			return
		}
		writePlain(w, http.StatusOK, "ready")
	})
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	// The body is a constant; a failed write means the client vanished, which
	// is not actionable here.
	_, _ = w.Write([]byte(body + "\n"))
}
