package api

import (
	"container/list"
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
// Security model:
//   - The cached creds are never stored in plaintext. The map key is
//     sha256(token), so cache contents alone can't be used to
//     re-authenticate.
//   - TTL bounds how long a since-rotated password keeps working through
//     identity-service; the operator picks a TTL short enough that
//     compromise has a bounded blast radius (24h is the default).
//   - Memory growth is bounded by `maxEntries`. Without this bound a
//     malicious client could spray distinct valid tokens (from many
//     captured creds, say) to grow the cache to OOM. When the cap is hit,
//     the least-recently-used entry is evicted.
//
// Lifecycle: process-local map, allocated once in New(). Lives in the
// Yandex Function container's RAM. Lost on cold start — every fresh
// container revalidates from scratch.
//
// Invalidation: TTL-only. There's no external invalidation hook today; a
// password rotation in S21 begins to take effect at most `ttl` after the
// rotation. Tightening that requires a webhook or a token-version field
// in the X-S21-Token, neither of which we want yet.
type S21TokenCache struct {
	mu         sync.Mutex // protects entries + lru
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	entries    map[string]*list.Element // hash → list element (lru)
	lru        *list.List               // values are *s21TokenEntry; front = most recently used
}

type s21TokenEntry struct {
	hash      string
	login     string
	expiresAt time.Time
}

// defaultS21TokenCacheMax caps the cache at 10000 distinct (login,
// password) pairs simultaneously. At 24h TTL that's enough headroom for
// every plausible legitimate user; way below where a single Yandex
// Function container (256 MB) would OOM.
const defaultS21TokenCacheMax = 10000

// NewS21TokenCache constructs a cache with the default size cap. `now` is
// injectable for tests; pass time.Now in production.
func NewS21TokenCache(ttl time.Duration, now func() time.Time) *S21TokenCache {
	return NewS21TokenCacheWithMax(ttl, defaultS21TokenCacheMax, now)
}

// NewS21TokenCacheWithMax constructs a cache with a caller-specified size
// cap. Used by tests to exercise the LRU eviction path without inserting
// 10000 entries.
func NewS21TokenCacheWithMax(ttl time.Duration, maxEntries int, now func() time.Time) *S21TokenCache {
	if now == nil {
		now = time.Now
	}
	if maxEntries < 1 {
		maxEntries = defaultS21TokenCacheMax
	}
	return &S21TokenCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        now,
		entries:    map[string]*list.Element{},
		lru:        list.New(),
	}
}

// Get returns the cached login for a previously-validated token if the
// entry is still fresh. (_, false) on miss / expiry. A hit promotes the
// entry to the front of the LRU list.
func (c *S21TokenCache) Get(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	key := hashToken(token)
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return "", false
	}
	e := el.Value.(*s21TokenEntry)
	if c.now().After(e.expiresAt) {
		// Expired — clear it eagerly so size accounting stays honest.
		c.lru.Remove(el)
		delete(c.entries, key)
		return "", false
	}
	c.lru.MoveToFront(el)
	return e.login, true
}

// Put records that `token` was successfully validated against S21 and
// resolved to `login`. The entry is valid for `ttl` from this moment.
// Promotes the entry to the front of the LRU list.
//
// If the cache is at capacity, the least-recently-used entry is evicted.
//
// Only call after a successful S21 authentication; never cache failures —
// that would lock out a user who fixed their password mid-window.
func (c *S21TokenCache) Put(token, login string) {
	if token == "" {
		return
	}
	key := hashToken(token)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*s21TokenEntry)
		e.login = login
		e.expiresAt = c.now().Add(c.ttl)
		c.lru.MoveToFront(el)
		return
	}
	e := &s21TokenEntry{
		hash:      key,
		login:     login,
		expiresAt: c.now().Add(c.ttl),
	}
	el := c.lru.PushFront(e)
	c.entries[key] = el
	c.evictLocked()
}

// Invalidate drops a specific token entry. Reserved for a future "the
// password has been rotated" signal; not currently invoked.
func (c *S21TokenCache) Invalidate(token string) {
	if token == "" {
		return
	}
	key := hashToken(token)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		c.lru.Remove(el)
		delete(c.entries, key)
	}
}

// Size returns the entry count. Used by tests; not part of the hot path.
func (c *S21TokenCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// evictLocked drops least-recently-used entries until the cache size is
// within the cap. Caller must hold c.mu.
func (c *S21TokenCache) evictLocked() {
	for len(c.entries) > c.maxEntries {
		back := c.lru.Back()
		if back == nil {
			return
		}
		c.lru.Remove(back)
		delete(c.entries, back.Value.(*s21TokenEntry).hash)
	}
}

// hashToken returns base64(sha256(token)). Used as the map key so we
// never hold plaintext "login:password" in memory.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(sum[:])
}
