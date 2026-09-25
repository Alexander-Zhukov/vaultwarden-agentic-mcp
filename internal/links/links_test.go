package links

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testMax = 64

func TestLinkIsSingleUseAndExpires(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	s := NewStore(clock, testMax)

	token, err := s.Issue(Link{Kind: KindValue, ItemID: "a", Field: "password", Expires: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Peek(token, KindValue); !ok {
		t.Fatal("peek must not consume")
	}
	if _, ok := s.Take(token, KindUpload); ok {
		t.Fatal("a request of the wrong kind must not take the link")
	}
	if _, ok := s.Take(token, KindValue, KindAttachment); !ok {
		t.Fatal("first take must succeed")
	}
	if _, ok := s.Take(token, KindValue); ok {
		t.Fatal("second take must fail")
	}

	expiring, err := s.Issue(Link{Kind: KindValue, ItemID: "a", Expires: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, ok := s.Take(expiring, KindValue); ok {
		t.Fatal("expired link must fail")
	}
}

func TestConcurrentTakeSucceedsOnce(t *testing.T) {
	t.Parallel()
	s := NewStore(time.Now, testMax)
	token, err := s.Issue(Link{Kind: KindValue, Expires: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, ok := s.Take(token, KindValue); ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d winners", wins.Load())
	}
}

func TestRevokeAndBound(t *testing.T) {
	t.Parallel()
	s := NewStore(time.Now, testMax)
	exp := time.Now().Add(time.Minute)
	for range testMax {
		if _, err := s.Issue(Link{ItemID: "x", Expires: exp}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Issue(Link{ItemID: "y", Expires: exp}); err == nil {
		t.Fatal("store must be bounded")
	}
	s.Revoke("x")
	if s.Outstanding() != 0 {
		t.Fatal("revoke must drop the item's links")
	}
}
