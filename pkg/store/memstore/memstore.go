// Package memstore is an in-memory store.Store, used by tests and as a
// safety fallback in the function entrypoint if YDB is unreachable at boot.
package memstore

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/store"
)

// Store is the in-memory store.
type Store struct {
	mu        sync.Mutex
	users     map[int64]store.User
	nicknames map[string]store.NicknameCacheEntry
}

// New returns an empty memstore.
func New() *Store {
	return &Store{
		users:     map[int64]store.User{},
		nicknames: map[string]store.NicknameCacheEntry{},
	}
}

// Close is a no-op.
func (s *Store) Close() error { return nil }

func (s *Store) Users() store.UserRepo                  { return userRepo{s} }
func (s *Store) NicknameCache() store.NicknameCacheRepo { return cacheRepo{s} }

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
