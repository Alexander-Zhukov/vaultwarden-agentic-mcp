package links

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestLinksExpireOnTheClock(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := NewStore(time.Now, testMax)
		token, err := s.Issue(Link{Kind: KindUpload, ItemID: "a", Expires: time.Now().Add(5 * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * time.Minute) //nolint:forbidigo // advances the synctest clock, no real wait
		if _, ok := s.Peek(token, KindUpload); !ok {
			t.Fatal("the link expired early")
		}
		time.Sleep(2 * time.Minute) //nolint:forbidigo // advances the synctest clock, no real wait
		if _, ok := s.Take(token, KindUpload); ok {
			t.Fatal("the link outlived its expiry")
		}
		if s.Outstanding() != 0 {
			t.Fatal("expired links must be swept")
		}
	})
}
