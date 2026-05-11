// Package store defines the storage interface for the identity service.
//
// Two implementations live in sub-packages: memstore (tests) and ydbstore
// (production).
package store

import (
	"context"
	"errors"
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

// ErrNotFound is the sentinel returned by single-row reads with no match.
var ErrNotFound = errors.New("store: not found")

// Store is the union of every repository the service needs.
type Store interface {
	Users() UserRepo
	NicknameCache() NicknameCacheRepo
	Close() error
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
