// Package ydbstore is the YDB-backed implementation of store.Store for the
// identity service.
package ydbstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/table"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/result/named"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/types"
	yc "github.com/ydb-platform/ydb-go-yc-metadata"

	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/store"
)

// Store is the YDB-backed store.Store.
type Store struct {
	driver *ydb.Driver
}

// Open connects to YDB via Cloud Function instance metadata auth.
func Open(ctx context.Context, connectionString string) (*Store, error) {
	d, err := ydb.Open(ctx, connectionString, yc.WithCredentials(), yc.WithInternalCA())
	if err != nil {
		return nil, fmt.Errorf("ydbstore.Open: %w", err)
	}
	return &Store{driver: d}, nil
}

// NewFromDriver wraps an externally-constructed *ydb.Driver as a Store. Used
// by the admin CLI, which authenticates against YDB with an IAM token from
// `yc iam create-token` rather than the in-function metadata service.
func NewFromDriver(d *ydb.Driver) *Store {
	return &Store{driver: d}
}

// Close shuts down the driver.
func (s *Store) Close() error {
	if s.driver == nil {
		return nil
	}
	return s.driver.Close(context.Background())
}

func (s *Store) Users() store.UserRepo                  { return userRepo{s} }
func (s *Store) NicknameCache() store.NicknameCacheRepo { return cacheRepo{s} }
func (s *Store) APIKeys() store.APIKeyRepo              { return apiKeyRepo{s} }

func (s *Store) doTx(ctx context.Context, fn func(ctx context.Context, tx table.TransactionActor) error) error {
	return s.driver.Table().DoTx(ctx, fn, table.WithIdempotent(),
		table.WithTxSettings(table.TxSettings(table.WithSerializableReadWrite())))
}

func (s *Store) doRO(ctx context.Context, fn func(ctx context.Context, sess table.Session) error) error {
	return s.driver.Table().Do(ctx, fn, table.WithIdempotent())
}

// ---------------- users ----------------

type userRepo struct{ s *Store }

const userColsSel = `telegram_id, nickname, campus_id, campus_name, coalition_name, created_at, updated_at`

func scanUser(res interface {
	ScanNamed(...named.Value) error
}) (store.User, error) {
	var u store.User
	var tid uint64
	err := res.ScanNamed(
		named.Required("telegram_id", &tid),
		named.Required("nickname", &u.Nickname),
		named.Required("campus_id", &u.CampusID),
		named.Required("campus_name", &u.CampusName),
		named.Required("coalition_name", &u.CoalitionName),
		named.Required("created_at", &u.CreatedAt),
		named.Required("updated_at", &u.UpdatedAt),
	)
	if err != nil {
		return u, err
	}
	u.TelegramID = int64(tid)
	return u, nil
}

func (r userRepo) GetByTelegramID(ctx context.Context, tid int64) (store.User, error) {
	var u store.User
	err := r.s.doRO(ctx, func(ctx context.Context, sess table.Session) error {
		_, res, err := sess.Execute(ctx, table.DefaultTxControl(),
			"DECLARE $tid AS Uint64; SELECT "+userColsSel+" FROM identity_users WHERE telegram_id = $tid;",
			table.NewQueryParameters(table.ValueParam("$tid", types.Uint64Value(uint64(tid)))))
		if err != nil {
			return err
		}
		defer res.Close()
		if err := res.NextResultSetErr(ctx); err != nil {
			return err
		}
		if !res.NextRow() {
			return store.ErrNotFound
		}
		u, err = scanUser(res)
		return err
	})
	return u, err
}

func (r userRepo) GetByTelegramIDs(ctx context.Context, tids []int64) ([]store.User, error) {
	if len(tids) == 0 {
		return nil, nil
	}
	// YDB doesn't have an IN list syntax convenient with parameter binding,
	// so we OR the conditions. Capped at 100 by the API.
	conds := make([]string, 0, len(tids))
	params := make([]table.ParameterOption, 0, len(tids))
	for i, id := range tids {
		name := fmt.Sprintf("$tid%d", i)
		conds = append(conds, "telegram_id = "+name)
		params = append(params, table.ValueParam(name, types.Uint64Value(uint64(id))))
	}
	declares := make([]string, 0, len(tids))
	for i := range tids {
		declares = append(declares, fmt.Sprintf("DECLARE $tid%d AS Uint64;", i))
	}
	q := strings.Join(declares, "\n") + "\nSELECT " + userColsSel + " FROM identity_users WHERE " + strings.Join(conds, " OR ") + ";"
	var out []store.User
	err := r.s.doRO(ctx, func(ctx context.Context, sess table.Session) error {
		_, res, err := sess.Execute(ctx, table.DefaultTxControl(), q, table.NewQueryParameters(params...))
		if err != nil {
			return err
		}
		defer res.Close()
		if err := res.NextResultSetErr(ctx); err != nil {
			return err
		}
		for res.NextRow() {
			u, err := scanUser(res)
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		return nil
	})
	return out, err
}

func (r userRepo) ListByNickname(ctx context.Context, nickname string) ([]store.User, error) {
	var out []store.User
	err := r.s.doRO(ctx, func(ctx context.Context, sess table.Session) error {
		_, res, err := sess.Execute(ctx, table.DefaultTxControl(),
			"DECLARE $n AS Utf8; SELECT "+userColsSel+" FROM identity_users WHERE nickname = $n ORDER BY created_at, telegram_id;",
			table.NewQueryParameters(table.ValueParam("$n", types.UTF8Value(nickname))))
		if err != nil {
			return err
		}
		defer res.Close()
		if err := res.NextResultSetErr(ctx); err != nil {
			return err
		}
		for res.NextRow() {
			u, err := scanUser(res)
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		return nil
	})
	return out, err
}

func (r userRepo) Upsert(ctx context.Context, u store.User) (store.User, error) {
	// Preserve CreatedAt on update. Two-step: read existing, then upsert.
	var existing store.User
	if got, err := r.GetByTelegramID(ctx, u.TelegramID); err == nil {
		existing = got
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	if !existing.CreatedAt.IsZero() {
		u.CreatedAt = existing.CreatedAt
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = u.UpdatedAt
	}
	const sql = `
DECLARE $tid AS Uint64;
DECLARE $nick AS Utf8;
DECLARE $cid AS Utf8;
DECLARE $cn AS Utf8;
DECLARE $coal AS Utf8;
DECLARE $cat AS Timestamp;
DECLARE $uat AS Timestamp;
UPSERT INTO identity_users (telegram_id, nickname, campus_id, campus_name, coalition_name, created_at, updated_at)
VALUES ($tid, $nick, $cid, $cn, $coal, $cat, $uat);`
	err := r.s.doTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
		_, err := tx.Execute(ctx, sql, table.NewQueryParameters(
			table.ValueParam("$tid", types.Uint64Value(uint64(u.TelegramID))),
			table.ValueParam("$nick", types.UTF8Value(u.Nickname)),
			table.ValueParam("$cid", types.UTF8Value(u.CampusID)),
			table.ValueParam("$cn", types.UTF8Value(u.CampusName)),
			table.ValueParam("$coal", types.UTF8Value(u.CoalitionName)),
			table.ValueParam("$cat", types.TimestampValueFromTime(u.CreatedAt.UTC())),
			table.ValueParam("$uat", types.TimestampValueFromTime(u.UpdatedAt.UTC())),
		))
		return err
	})
	return u, err
}

func (r userRepo) Delete(ctx context.Context, tid int64) error {
	// Pre-check existence to honour ErrNotFound semantics.
	if _, err := r.GetByTelegramID(ctx, tid); errors.Is(err, store.ErrNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return r.s.doTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
		_, err := tx.Execute(ctx,
			"DECLARE $tid AS Uint64; DELETE FROM identity_users WHERE telegram_id = $tid;",
			table.NewQueryParameters(table.ValueParam("$tid", types.Uint64Value(uint64(tid)))))
		return err
	})
}

// ---------------- nickname cache ----------------

type cacheRepo struct{ s *Store }

func (r cacheRepo) Get(ctx context.Context, nickname string) (store.NicknameCacheEntry, error) {
	var e store.NicknameCacheEntry
	err := r.s.doRO(ctx, func(ctx context.Context, sess table.Session) error {
		_, res, err := sess.Execute(ctx, table.DefaultTxControl(),
			"DECLARE $n AS Utf8; SELECT nickname, campus_id, campus_name, coalition_name, cached_at FROM s21_nickname_cache WHERE nickname = $n;",
			table.NewQueryParameters(table.ValueParam("$n", types.UTF8Value(strings.ToLower(nickname)))))
		if err != nil {
			return err
		}
		defer res.Close()
		if err := res.NextResultSetErr(ctx); err != nil {
			return err
		}
		if !res.NextRow() {
			return store.ErrNotFound
		}
		return res.ScanNamed(
			named.Required("nickname", &e.Nickname),
			named.Required("campus_id", &e.CampusID),
			named.Required("campus_name", &e.CampusName),
			named.Required("coalition_name", &e.CoalitionName),
			named.Required("cached_at", &e.CachedAt),
		)
	})
	return e, err
}

func (r cacheRepo) Upsert(ctx context.Context, e store.NicknameCacheEntry) error {
	if e.CachedAt.IsZero() {
		e.CachedAt = time.Now().UTC()
	}
	const sql = `
DECLARE $n AS Utf8;
DECLARE $cid AS Utf8;
DECLARE $cn AS Utf8;
DECLARE $coal AS Utf8;
DECLARE $cat AS Timestamp;
UPSERT INTO s21_nickname_cache (nickname, campus_id, campus_name, coalition_name, cached_at)
VALUES ($n, $cid, $cn, $coal, $cat);`
	return r.s.doTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
		_, err := tx.Execute(ctx, sql, table.NewQueryParameters(
			table.ValueParam("$n", types.UTF8Value(strings.ToLower(e.Nickname))),
			table.ValueParam("$cid", types.UTF8Value(e.CampusID)),
			table.ValueParam("$cn", types.UTF8Value(e.CampusName)),
			table.ValueParam("$coal", types.UTF8Value(e.CoalitionName)),
			table.ValueParam("$cat", types.TimestampValueFromTime(e.CachedAt.UTC())),
		))
		return err
	})
}

// ---------------- api keys ----------------

type apiKeyRepo struct{ s *Store }

const apiKeyColsSel = `key_hash, name, scopes, created_at, revoked_at, created_by_telegram_id`

func scanAPIKey(res interface {
	ScanNamed(...named.Value) error
}) (store.APIKey, error) {
	var k store.APIKey
	var revokedAt *time.Time
	var createdBy *uint64
	err := res.ScanNamed(
		named.Required("key_hash", &k.KeyHash),
		named.Required("name", &k.Name),
		named.Required("scopes", &k.Scopes),
		named.Required("created_at", &k.CreatedAt),
		named.Optional("revoked_at", &revokedAt),
		named.Optional("created_by_telegram_id", &createdBy),
	)
	if err != nil {
		return k, err
	}
	k.RevokedAt = revokedAt
	if createdBy != nil {
		k.CreatedByTelegramID = int64(*createdBy)
	}
	return k, nil
}

func (r apiKeyRepo) GetByHash(ctx context.Context, h string) (store.APIKey, error) {
	var k store.APIKey
	err := r.s.doRO(ctx, func(ctx context.Context, sess table.Session) error {
		_, res, err := sess.Execute(ctx, table.DefaultTxControl(),
			"DECLARE $h AS Utf8; SELECT "+apiKeyColsSel+" FROM api_keys WHERE key_hash = $h;",
			table.NewQueryParameters(table.ValueParam("$h", types.UTF8Value(h))))
		if err != nil {
			return err
		}
		defer res.Close()
		if err := res.NextResultSetErr(ctx); err != nil {
			return err
		}
		if !res.NextRow() {
			return store.ErrNotFound
		}
		k, err = scanAPIKey(res)
		return err
	})
	return k, err
}

func (r apiKeyRepo) Insert(ctx context.Context, k store.APIKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	// Atomic check-then-insert: serializable tx scans active rows for name
	// or creator collisions, then upserts.
	return r.s.doTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
		// 1. Name collision.
		res, err := tx.Execute(ctx,
			"DECLARE $n AS Utf8; SELECT key_hash FROM api_keys WHERE name = $n AND revoked_at IS NULL LIMIT 1;",
			table.NewQueryParameters(table.ValueParam("$n", types.UTF8Value(k.Name))))
		if err != nil {
			return err
		}
		if err := res.NextResultSetErr(ctx); err != nil {
			_ = res.Close()
			return err
		}
		if res.NextRow() {
			_ = res.Close()
			return store.ErrKeyNameInUse
		}
		_ = res.Close()
		// 2. Creator-has-active-key, when creator is set.
		if k.CreatedByTelegramID != 0 {
			res, err := tx.Execute(ctx,
				"DECLARE $tid AS Uint64; SELECT key_hash FROM api_keys WHERE created_by_telegram_id = $tid AND revoked_at IS NULL LIMIT 1;",
				table.NewQueryParameters(table.ValueParam("$tid", types.Uint64Value(uint64(k.CreatedByTelegramID)))))
			if err != nil {
				return err
			}
			if err := res.NextResultSetErr(ctx); err != nil {
				_ = res.Close()
				return err
			}
			if res.NextRow() {
				_ = res.Close()
				return store.ErrCreatorHasActiveKey
			}
			_ = res.Close()
		}
		// 3. Insert.
		var byVal types.Value = types.NullValue(types.TypeUint64)
		if k.CreatedByTelegramID != 0 {
			byVal = types.OptionalValue(types.Uint64Value(uint64(k.CreatedByTelegramID)))
		}
		const sql = `
DECLARE $h AS Utf8;
DECLARE $n AS Utf8;
DECLARE $sc AS Utf8;
DECLARE $cat AS Timestamp;
DECLARE $by AS Uint64?;
UPSERT INTO api_keys (key_hash, name, scopes, created_at, revoked_at, created_by_telegram_id)
VALUES ($h, $n, $sc, $cat, NULL, $by);`
		_, err = tx.Execute(ctx, sql, table.NewQueryParameters(
			table.ValueParam("$h", types.UTF8Value(k.KeyHash)),
			table.ValueParam("$n", types.UTF8Value(k.Name)),
			table.ValueParam("$sc", types.UTF8Value(k.Scopes)),
			table.ValueParam("$cat", types.TimestampValueFromTime(k.CreatedAt.UTC())),
			table.ValueParam("$by", byVal),
		))
		return err
	})
}

func (r apiKeyRepo) RevokeByName(ctx context.Context, name string, by int64, at time.Time) error {
	return r.s.doTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
		// Look up the active key with this name. Apply creator filter when
		// by != 0 — bot-driven revoke can only touch the caller's own keys.
		q := "DECLARE $n AS Utf8; SELECT key_hash, created_by_telegram_id FROM api_keys WHERE name = $n AND revoked_at IS NULL LIMIT 1;"
		res, err := tx.Execute(ctx, q,
			table.NewQueryParameters(table.ValueParam("$n", types.UTF8Value(name))))
		if err != nil {
			return err
		}
		if err := res.NextResultSetErr(ctx); err != nil {
			_ = res.Close()
			return err
		}
		if !res.NextRow() {
			_ = res.Close()
			return store.ErrNotFound
		}
		var hash string
		var ownerOpt *uint64
		if err := res.ScanNamed(
			named.Required("key_hash", &hash),
			named.Optional("created_by_telegram_id", &ownerOpt),
		); err != nil {
			_ = res.Close()
			return err
		}
		_ = res.Close()
		if by != 0 {
			if ownerOpt == nil || int64(*ownerOpt) != by {
				return store.ErrNotFound
			}
		}
		_, err = tx.Execute(ctx,
			"DECLARE $h AS Utf8; DECLARE $rat AS Timestamp; UPDATE api_keys SET revoked_at = $rat WHERE key_hash = $h;",
			table.NewQueryParameters(
				table.ValueParam("$h", types.UTF8Value(hash)),
				table.ValueParam("$rat", types.TimestampValueFromTime(at.UTC())),
			))
		return err
	})
}

func (r apiKeyRepo) List(ctx context.Context) ([]store.APIKey, error) {
	var out []store.APIKey
	err := r.s.doRO(ctx, func(ctx context.Context, sess table.Session) error {
		_, res, err := sess.Execute(ctx, table.DefaultTxControl(),
			"SELECT "+apiKeyColsSel+" FROM api_keys ORDER BY created_at, name;",
			table.NewQueryParameters())
		if err != nil {
			return err
		}
		defer res.Close()
		if err := res.NextResultSetErr(ctx); err != nil {
			return err
		}
		for res.NextRow() {
			k, err := scanAPIKey(res)
			if err != nil {
				return err
			}
			out = append(out, k)
		}
		return nil
	})
	return out, err
}
