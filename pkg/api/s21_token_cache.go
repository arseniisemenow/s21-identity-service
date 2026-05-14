package api

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// S21TokenCache memoizes "this X-S21-Token has already been validated
// against the S21 API and was accepted, with the resulting login = L,
// valid until T."
//
// The cache eliminates the per-request S21 round-trip on hot paths. With
// no cache, every inbound request (from ttbot, identity-bot, or anything
// else that holds S21 creds) calls S21's DashboardHeaderGetInfo to verify
// the credentials — a call that can take seconds and is the dominant cost
// observed in production. With the cache, a request whose creds were
// validated within the last `ttl` skips that round-trip entirely.
//
// Security model: the cached creds are never stored in plaintext. The
// cache is keyed by sha256(token), so cache contents alone can't be used
// to re-authenticate. TTL bounds how long a since-rotated password keeps
// working through identity-service; the operator picks a TTL short enough
// that compromise has a bounded blast radius (24h is the default).
//
// Lifecycle: process-local map, allocated once in New() / NewWithCache().
// Lives in the Yandex Function container's RAM. Lost on cold start —
// every fresh container revalidates from scratch.
//
// Invalidation: TTL-only. There's no external invalidation hook today; a
// password rotation in S21 begins to take effect at most `ttl` after the
// rotation. Tightening that requires a Webhook or a token-version field
// in the X-S21-Token, neither of which we want yet.
type S21TokenCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	now     func() time.Time
	entries map[string]s21TokenEntry
}

type s21TokenEntry struct {
	login     string
	expiresAt time.Time
}

// NewS21TokenCache constructs a cache. `now` is injectable for tests; pass
// time.Now in production.
func NewS21TokenCache(ttl time.Duration, now func() time.Time) *S21TokenCache {
	if now == nil {
		now = time.Now
	}
	return &S21TokenCache{
		ttl:     ttl,
		now:     now,
		entries: map[string]s21TokenEntry{},
	}
}

// Get returns the cached login for a previously-validated token if the
// entry is still fresh. (_, false) on miss / expiry.
func (c *S21TokenCache) Get(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	key := hashToken(token)
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return "", false
	}
	if c.now().After(e.expiresAt) {
		return "", false
	}
	return e.login, true
}

// Put records that `token` was successfully validated against S21 and
// resolved to `login`. The entry is valid for `ttl` from this moment.
//
// Only call after a successful S21 authentication; never cache failures —
// that would lock out a user who fixed their password mid-window.
func (c *S21TokenCache) Put(token, login string) {
	if token == "" {
		return
	}
	key := hashToken(token)
	c.mu.Lock()
	c.entries[key] = s21TokenEntry{
		login:     login,
		expiresAt: c.now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Invalidate drops a specific token entry. Reserved for a future "the
// password has been rotated" signal; not currently invoked.
func (c *S21TokenCache) Invalidate(token string) {
	if token == "" {
		return
	}
	c.mu.Lock()
	delete(c.entries, hashToken(token))
	c.mu.Unlock()
}

// Size returns the entry count. Used by tests; not part of the hot path.
func (c *S21TokenCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// hashToken returns base64(sha256(token)). Used as the map key so we never
// hold plaintext "login:password" in memory.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(sum[:])
}
