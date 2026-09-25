package obs

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
)

// Recover turns a panic in a handler into a 500 and a log record. A panic in one
// request must not take down a process that holds an unlocked vault.
func Recover(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			logger.Error("panic in handler",
				slog.String("path", redactPath(r.URL.Path)),
				slog.Any("panic", recovered),
				slog.String("stack", string(debug.Stack())),
			)
			writePlain(w, http.StatusInternalServerError, "internal error")
		}()
		next.ServeHTTP(w, r)
	})
}

// redactPath keeps the route of a one-time link but not its token, which is a
// live credential until redeemed.
func redactPath(path string) string {
	for _, prefix := range []string{"/v1/links/", "/v1/upload/"} {
		if strings.HasPrefix(path, prefix) {
			return prefix + "[token]"
		}
	}
	return path
}
