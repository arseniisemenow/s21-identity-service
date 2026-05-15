// Package store defines the storage interface for the identity service.
//
// Two implementations live in sub-packages: memstore (tests) and ydbstore
// (production).
package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

// User is the storage-layer user row.
type User struct {
	TelegramID    int64
	Nickname      string
	CampusID      string
	CampusName    string
	CoalitionName string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NicknameCacheEntry is one row in the s21_nickname_cache table — a lazy
// record of "this S21 nickname has been validated against S21 at this time".
type NicknameCacheEntry struct {
	Nickname      string
	CampusID      string
	CampusName    string
	CoalitionName string
	CachedAt      time.Time
}

// S21TokenCacheEntry is one row in the s21_token_cache table — a durable
// record of "this X-S21-Token was validated against S21 and resolved to
// this login; the entry is good until ExpiresAt". TokenHash is the
// base64(sha256("login:password")) primary key — plaintext creds are
// NEVER stored, only the hash.
//
// The durable cache exists because the Yandex Function container is
// recycled after ~10–15 min idle, so the in-process LRU on its own
// re-validates against S21 too often. Persisting hits to YDB means a
// fresh container wakes up "already trusting" recent tokens.
type S21TokenCacheEntry struct {
	TokenHash string
	Login     string
	ExpiresAt time.Time
}

// APIKey is one row in api_keys. Authenticates a client (ttbot, identity-bot,
// etc.) at the perimeter. Stored as sha256 of the plaintext — never plaintext.
// Combined with X-S21-Token on every endpoint (defense in depth).
type APIKey struct {
	KeyHash             string     // base64-stdencoded sha256 of the plaintext key
	Name                string     // human label; unique among non-revoked rows
	Scopes              string     // comma-separated: "read", "write", or "read,write"
	CreatedAt           time.Time  // UTC
	RevokedAt           *time.Time // nil = active; non-nil = soft-deleted
	CreatedByTelegramID int64      // 0 = no specific owner (CLI-minted, e.g. for ttbot/identity-bot envs)
}

// HasScope reports whether this key holds a given scope. Scopes are matched
// case-sensitively after trimming whitespace.
func (k APIKey) HasScope(scope string) bool {
	for _, s := range splitScopes(k.Scopes) {
		if s == scope {
			return true
		}
	}
	return false
}

// IsActive reports whether the key is currently usable (not revoked).
func (k APIKey) IsActive() bool { return k.RevokedAt == nil }

func splitScopes(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ErrNotFound is the sentinel returned by single-row reads with no match.
var ErrNotFound = errors.New("store: not found")

// ErrKeyNameInUse is returned by APIKeyRepo.Insert when a non-revoked key
// with the same name already exists.
var ErrKeyNameInUse = errors.New("store: key name already in use")

// ErrCreatorHasActiveKey is returned by APIKeyRepo.Insert when the given
// CreatedByTelegramID already has a non-revoked key. Enforces the
// "one key per user" rule for bot-issued keys. Does not apply when
// CreatedByTelegramID == 0 (CLI-minted keys).
var ErrCreatorHasActiveKey = errors.New("store: creator already has an active key")

// Store is the union of every repository the service needs.
type Store interface {
	Users() UserRepo
	NicknameCache() NicknameCacheRepo
	APIKeys() APIKeyRepo
	S21TokenCache() S21TokenCacheRepo
	Close() error
}

// S21TokenCacheRepo persists "this X-S21-Token (hashed) was accepted by
// S21 and resolved to this login, valid until ExpiresAt". Read on every
// inbound request before falling back to a live S21 round-trip; written
// after a successful round-trip. Failures are never persisted — that
// would lock out a user who fixed their password mid-window.
type S21TokenCacheRepo interface {
	// Get returns the row matching `tokenHash`. Returns ErrNotFound when
	// nothing matches. The caller is responsible for the freshness check
	// against ExpiresAt — the repo doesn't filter by time so the call
	// site can log "expired hit, will revalidate" if it wants.
	Get(ctx context.Context, tokenHash string) (S21TokenCacheEntry, error)
	// Upsert writes (or overwrites) the row. Idempotent.
	Upsert(ctx context.Context, e S21TokenCacheEntry) error
}

// APIKeyRepo persists issued API keys. Keys are stored only as sha256(plaintext)
// in KeyHash; the plaintext is shown to the operator/admin exactly once at
// creation and never recoverable from storage.
type APIKeyRepo interface {
	// GetByHash returns the row matching a sha256 hash. The middleware
	// hashes the inbound X-Api-Key and calls this. Returns ErrNotFound when
	// nothing matches.
	GetByHash(ctx context.Context, keyHash string) (APIKey, error)
	// Insert atomically checks "name not in use among non-revoked rows" and
	// "creator has no active key (unless creator == 0)", then inserts the row.
	Insert(ctx context.Context, k APIKey) error
	// RevokeByName marks the active key with the given name as revoked.
	// If byTelegramID != 0, the revoke succeeds only when CreatedByTelegramID
	// matches — enforcing "users can only revoke their own keys" for the bot
	// path. Returns ErrNotFound when no matching active row exists.
	RevokeByName(ctx context.Context, name string, byTelegramID int64, at time.Time) error
	// List returns every row, active and revoked, ordered by created_at asc.
	// Used by the CLI to show what's been issued.
	List(ctx context.Context) ([]APIKey, error)
	// CountByCreatorSince returns the number of keys created by
	// `byTelegramID` whose CreatedAt is at or after `since`. Both active
	// and revoked rows count. Used to rate-limit POST /admin/keys —
	// without this an attacker can rapidly create-revoke-create-revoke,
	// consuming storage and enumerating name conflicts.
	CountByCreatorSince(ctx context.Context, byTelegramID int64, since time.Time) (int, error)
}

// UserRepo persists the (telegram_id ↔ nickname) bindings.
type UserRepo interface {
	GetByTelegramID(ctx context.Context, telegramID int64) (User, error)
	GetByTelegramIDs(ctx context.Context, telegramIDs []int64) ([]User, error)
	// ListByNickname returns every row whose nickname matches, ordered by
	// CreatedAt ascending (earliest first). Two telegram_ids may share one
	// nickname; the caller decides how to disambiguate.
	ListByNickname(ctx context.Context, nickname string) ([]User, error)
	Upsert(ctx context.Context, u User) (User, error)
	Delete(ctx context.Context, telegramID int64) error
}

// NicknameCacheRepo caches the set of valid S21 nicknames. We populate it
// lazily on writes: when a PUT comes in with an unknown nickname we call
// S21 once to confirm, then store the result here.
type NicknameCacheRepo interface {
	Get(ctx context.Context, nickname string) (NicknameCacheEntry, error)
	Upsert(ctx context.Context, e NicknameCacheEntry) error
}
