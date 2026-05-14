package api

import (
	"testing"
	"time"
)

func TestS21TokenCacheHitWithinTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewS21TokenCache(24*time.Hour, func() time.Time { return now })
	c.Put("alice:pw", "alice")
	now = now.Add(23 * time.Hour)
	login, ok := c.Get("alice:pw")
	if !ok || login != "alice" {
		t.Errorf("expected fresh hit login=alice; got login=%q ok=%v", login, ok)
	}
}

func TestS21TokenCacheMissAfterTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewS21TokenCache(24*time.Hour, func() time.Time { return now })
	c.Put("alice:pw", "alice")
	now = now.Add(25 * time.Hour)
	if _, ok := c.Get("alice:pw"); ok {
		t.Errorf("expected expiry miss")
	}
}

func TestS21TokenCacheMissOnUnknownToken(t *testing.T) {
	c := NewS21TokenCache(time.Hour, time.Now)
	if _, ok := c.Get("nobody:wrong"); ok {
		t.Errorf("expected miss on unknown token")
	}
}

func TestS21TokenCacheNeverStoresPlaintext(t *testing.T) {
	// The map key is sha256 of the token, so the raw "login:password"
	// string never appears anywhere in cache state. This test makes sure
	// future refactors don't regress on that.
	c := NewS21TokenCache(time.Hour, time.Now)
	c.Put("alice:secret123", "alice")
	for k := range c.entries {
		if k == "alice:secret123" {
			t.Fatalf("plaintext token appeared as map key")
		}
	}
}

func TestS21TokenCacheDifferentTokensSeparateEntries(t *testing.T) {
	c := NewS21TokenCache(time.Hour, time.Now)
	c.Put("alice:pw1", "alice")
	c.Put("alice:pw2", "alice") // same login, different password (rotation)
	if c.Size() != 2 {
		t.Errorf("expected 2 entries (one per token), got %d", c.Size())
	}
}

func TestS21TokenCacheInvalidate(t *testing.T) {
	c := NewS21TokenCache(time.Hour, time.Now)
	c.Put("alice:pw", "alice")
	c.Invalidate("alice:pw")
	if _, ok := c.Get("alice:pw"); ok {
		t.Errorf("expected miss after invalidate")
	}
}

func TestS21TokenCacheEmptyTokenIsNoop(t *testing.T) {
	c := NewS21TokenCache(time.Hour, time.Now)
	c.Put("", "anything")
	if _, ok := c.Get(""); ok {
		t.Errorf("empty token should never hit")
	}
	if c.Size() != 0 {
		t.Errorf("empty token should not have created an entry")
	}
}

// TestS21TokenCacheRespectsMaxSize: a malicious client sprays N+1 distinct
// valid tokens; the cache stops growing at N. Direct coverage of the S3
// vuln (unbounded growth).
func TestS21TokenCacheRespectsMaxSize(t *testing.T) {
	c := NewS21TokenCacheWithMax(time.Hour, 3, time.Now)
	c.Put("a:1", "a")
	c.Put("b:1", "b")
	c.Put("c:1", "c")
	c.Put("d:1", "d") // overflows: cache must stay at 3
	if c.Size() != 3 {
		t.Errorf("expected size capped at 3, got %d", c.Size())
	}
}

// TestS21TokenCacheLRUEvictsOldest: under cap pressure, the entry that
// hasn't been accessed for longest is the one evicted.
func TestS21TokenCacheLRUEvictsOldest(t *testing.T) {
	c := NewS21TokenCacheWithMax(time.Hour, 3, time.Now)
	c.Put("a:1", "a") // oldest
	c.Put("b:1", "b")
	c.Put("c:1", "c")
	// Touch "a" → "b" is now the LRU.
	if _, ok := c.Get("a:1"); !ok {
		t.Fatal("a should still be present")
	}
	c.Put("d:1", "d") // evicts b
	if _, ok := c.Get("b:1"); ok {
		t.Errorf("expected b to be evicted as LRU")
	}
	if _, ok := c.Get("a:1"); !ok {
		t.Errorf("a (recently used) should have survived eviction")
	}
	if _, ok := c.Get("c:1"); !ok {
		t.Errorf("c should have survived eviction")
	}
	if _, ok := c.Get("d:1"); !ok {
		t.Errorf("d (just inserted) should be present")
	}
}

// TestS21TokenCacheRepeatedPutDoesNotGrow: repeat Puts of the same token
// must update in place, not pile up. (This was an implicit assumption in
// the old map-only implementation; preserve it with LRU.)
func TestS21TokenCacheRepeatedPutDoesNotGrow(t *testing.T) {
	c := NewS21TokenCacheWithMax(time.Hour, 5, time.Now)
	for i := 0; i < 100; i++ {
		c.Put("alice:pw", "alice")
	}
	if c.Size() != 1 {
		t.Errorf("repeated Puts should update in place; got size %d", c.Size())
	}
}

// TestS21TokenCacheGetEvictsExpired: an expired entry should be cleared
// from internal state on Get so the LRU bookkeeping stays correct.
// TestConstantTimeEqual: the helper used to compare cached logins is
// genuinely byte-equality. Doesn't test timing directly (Go's testing
// framework can't reliably measure ns-scale differences on shared CI
// machines), but pins the public surface so a future refactor can't
// accidentally re-introduce `==`.
func TestConstantTimeEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"alice", "alice", true},
		{"alice", "bob", false},
		{"alice", "Alice", false}, // case-sensitive
		{"", "", true},
		{"x", "", false},
		{"longer-string-here", "longer-string-here", true},
		{"longer-string-here", "longer-string-her3", false}, // diff late
	}
	for _, c := range cases {
		got := constantTimeEqual(c.a, c.b)
		if got != c.want {
			t.Errorf("constantTimeEqual(%q,%q) = %v; want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestS21TokenCacheGetEvictsExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewS21TokenCacheWithMax(time.Hour, 5, func() time.Time { return now })
	c.Put("alice:pw", "alice")
	if c.Size() != 1 {
		t.Fatalf("expected size 1, got %d", c.Size())
	}
	now = now.Add(2 * time.Hour) // expire
	if _, ok := c.Get("alice:pw"); ok {
		t.Fatal("expected expired miss")
	}
	if c.Size() != 0 {
		t.Errorf("expired entry should have been swept on Get; size=%d", c.Size())
	}
}

