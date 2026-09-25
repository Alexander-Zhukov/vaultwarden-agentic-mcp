package mcpserver

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestRateLimiterWindow(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		l := newRateLimiter(2, time.Minute, time.Now)
		first, second, third := l.allow("a"), l.allow("a"), l.allow("a")
		if !first || !second || third {
			t.Fatal("the third call inside the window must be refused")
		}
		if !l.allow("b") {
			t.Fatal("clients are counted separately")
		}
		time.Sleep(61 * time.Second) //nolint:forbidigo // advances the synctest clock, no real wait
		if !l.allow("a") {
			t.Fatal("the window must slide")
		}
	})
}

func TestShareBookOwnership(t *testing.T) {
	t.Parallel()
	b := newShareBook()
	b.add("s1", "op")
	if b.take("s1", "other") {
		t.Fatal("another client took the share")
	}
	if !b.take("s1", "op") || b.take("s1", "op") {
		t.Fatal("the owner takes it exactly once")
	}
}
