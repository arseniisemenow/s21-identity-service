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

