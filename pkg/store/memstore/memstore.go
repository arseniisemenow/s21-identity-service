// Package memstore is an in-memory store.Store, used by tests and as a
// safety fallback in the function entrypoint if YDB is unreachable at boot.
package memstore

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arseniisemenow/s21-identity-service/pkg/store"
)

// Store is the in-memory store.
type Store struct {
	mu          sync.Mutex
	users       map[int64]store.User
	nicknames   map[string]store.NicknameCacheEntry
	apiKeys     map[string]store.APIKey // keyed by KeyHash
	tokenCache  map[string]store.S21TokenCacheEntry
}

// New returns an empty memstore.
func New() *Store {
	return &Store{
		users:      map[int64]store.User{},
		nicknames:  map[string]store.NicknameCacheEntry{},
		apiKeys:    map[string]store.APIKey{},
		tokenCache: map[string]store.S21TokenCacheEntry{},
	}
}

// Close is a no-op.
func (s *Store) Close() error { return nil }

func (s *Store) Users() store.UserRepo                    { return userRepo{s} }
func (s *Store) NicknameCache() store.NicknameCacheRepo   { return cacheRepo{s} }
func (s *Store) APIKeys() store.APIKeyRepo                { return apiKeyRepo{s} }
func (s *Store) S21TokenCache() store.S21TokenCacheRepo   { return tokenCacheRepo{s} }

// ---------------- users ----------------

type userRepo struct{ s *Store }

func (r userRepo) GetByTelegramID(_ context.Context, tid int64) (store.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	u, ok := r.s.users[tid]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (r userRepo) GetByTelegramIDs(_ context.Context, tids []int64) ([]store.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	out := make([]store.User, 0, len(tids))
	for _, id := range tids {
		if u, ok := r.s.users[id]; ok {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TelegramID < out[j].TelegramID })
	return out, nil
}

func (r userRepo) ListByNickname(_ context.Context, nickname string) ([]store.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.User
	for _, u := range r.s.users {
		if strings.EqualFold(u.Nickname, nickname) {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].TelegramID < out[j].TelegramID
	})
	return out, nil
}

func (r userRepo) Upsert(_ context.Context, u store.User) (store.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if existing, ok := r.s.users[u.TelegramID]; ok {
		// Preserve CreatedAt on update.
		u.CreatedAt = existing.CreatedAt
	}
	r.s.users[u.TelegramID] = u
	return u, nil
}

func (r userRepo) Delete(_ context.Context, tid int64) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.users[tid]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.users, tid)
	return nil
}

// ---------------- nickname cache ----------------

type cacheRepo struct{ s *Store }

func (r cacheRepo) Get(_ context.Context, nick string) (store.NicknameCacheEntry, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e, ok := r.s.nicknames[strings.ToLower(nick)]
	if !ok {
		return store.NicknameCacheEntry{}, store.ErrNotFound
	}
	return e, nil
}

func (r cacheRepo) Upsert(_ context.Context, e store.NicknameCacheEntry) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.nicknames[strings.ToLower(e.Nickname)] = e
	return nil
}

// ---------------- api keys ----------------

type apiKeyRepo struct{ s *Store }

func (r apiKeyRepo) GetByHash(_ context.Context, h string) (store.APIKey, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k, ok := r.s.apiKeys[h]
	if !ok {
		return store.APIKey{}, store.ErrNotFound
	}
	return k, nil
}

func (r apiKeyRepo) Insert(_ context.Context, k store.APIKey) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, existing := range r.s.apiKeys {
		if existing.RevokedAt != nil {
			continue
		}
		if existing.Name == k.Name {
			return store.ErrKeyNameInUse
		}
		if k.CreatedByTelegramID != 0 && existing.CreatedByTelegramID == k.CreatedByTelegramID {
			return store.ErrCreatorHasActiveKey
		}
	}
	r.s.apiKeys[k.KeyHash] = k
	return nil
}

func (r apiKeyRepo) RevokeByName(_ context.Context, name string, by int64, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for hash, k := range r.s.apiKeys {
		if k.RevokedAt != nil || k.Name != name {
			continue
		}
		if by != 0 && k.CreatedByTelegramID != by {
			continue
		}
		atCopy := at.UTC()
		k.RevokedAt = &atCopy
		r.s.apiKeys[hash] = k
		return nil
	}
	return store.ErrNotFound
}

func (r apiKeyRepo) List(_ context.Context) ([]store.APIKey, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	out := make([]store.APIKey, 0, len(r.s.apiKeys))
	for _, k := range r.s.apiKeys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (r apiKeyRepo) CountByCreatorSince(_ context.Context, by int64, since time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	count := 0
	for _, k := range r.s.apiKeys {
		if k.CreatedByTelegramID == by && !k.CreatedAt.Before(since) {
			count++
		}
	}
	return count, nil
}

// ---------------- s21 token cache ----------------

type tokenCacheRepo struct{ s *Store }

func (r tokenCacheRepo) Get(_ context.Context, hash string) (store.S21TokenCacheEntry, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e, ok := r.s.tokenCache[hash]
	if !ok {
		return store.S21TokenCacheEntry{}, store.ErrNotFound
	}
	return e, nil
}

func (r tokenCacheRepo) Upsert(_ context.Context, e store.S21TokenCacheEntry) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.tokenCache[e.TokenHash] = e
	return nil
}
