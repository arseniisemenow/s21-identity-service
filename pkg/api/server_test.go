package api_test

import (
	"bytes"
	"context"
	crypto_sha256 "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arseniisemenow/s21-identity-service/pkg/api"
	"github.com/arseniisemenow/s21-identity-service/pkg/s21"
	"github.com/arseniisemenow/s21-identity-service/pkg/store"
	"github.com/arseniisemenow/s21-identity-service/pkg/store/memstore"
)

// world is the test fixture for the identity service. Each test calls
// newWorld(t) to get a fresh server with an httptest.Server in front.
type world struct {
	t   *testing.T
	srv *api.Server
	ts  *httptest.Server
	s21 *s21.Mock
	st  *memstore.Store
}

func newWorld(t *testing.T) *world {
	t.Helper()
	st := memstore.New()
	sm := s21.NewMock()
	// Pre-register a default admin so authenticate() succeeds.
	sm.SetUser("evangelm", "secret", s21.Profile{
		Login: "evangelm", CampusID: "kazan-id", CampusName: "21 Kazan", CoalitionName: "Terra",
	})
	sm.SetAdminPassword("evangelm", "secret")
	srv := api.New(st, sm)
	// Tests run over plain HTTP via httptest, and tests don't issue API keys.
	srv.EnforceHTTPS = false
	srv.EnforceAPIKey = false
	srv.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &world{t: t, srv: srv, ts: ts, s21: sm, st: st}
}

// do performs an HTTP request against the test server with the default auth.
func (w *world) do(method, path, token string, body any) (*http.Response, []byte) {
	return w.doWithKey(method, path, token, "", body)
}

// doWithKey is `do` plus an X-Api-Key header.
func (w *world) doWithKey(method, path, token, apiKey string, body any) (*http.Response, []byte) {
	w.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, w.ts.URL+path, rdr)
	if token != "" {
		req.Header.Set("X-S21-Token", token)
	}
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// mintKey inserts an API-key row directly via the store (bypasses HTTP).
// Returns the plaintext key the caller should put in X-Api-Key. Test-only
// helper for the scope-gating tests.
func (w *world) mintKey(name, scopes string, createdBy int64) string {
	plaintext := "test-key-" + name
	hash := sha256ToBase64(plaintext)
	if err := w.st.APIKeys().Insert(context.Background(), store.APIKey{
		KeyHash:             hash,
		Name:                name,
		Scopes:              scopes,
		CreatedAt:           w.srv.Now().UTC(),
		CreatedByTelegramID: createdBy,
	}); err != nil {
		w.t.Fatal(err)
	}
	return plaintext
}

func sha256ToBase64(s string) string {
	sum := crypto_sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ---------- auth ----------

func TestAuth_MissingToken(t *testing.T) {
	w := newWorld(t)
	resp, raw := w.do(http.MethodGet, "/users/by_telegram/1", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d body=%s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "missing_token") {
		t.Errorf("expected missing_token code, got %s", raw)
	}
}

func TestAuth_MalformedToken(t *testing.T) {
	w := newWorld(t)
	resp, raw := w.do(http.MethodGet, "/users/by_telegram/1", "noseparator", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d body=%s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "malformed_token") {
		t.Errorf("expected malformed_token, got %s", raw)
	}
}

func TestAuth_InvalidCredentials(t *testing.T) {
	w := newWorld(t)
	resp, raw := w.do(http.MethodGet, "/users/by_telegram/1", "evangelm:wrong", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d body=%s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "invalid_token") {
		t.Errorf("expected invalid_token, got %s", raw)
	}
}

// ---------- GET /users/by_telegram ----------

func TestGetByTelegram_NotFound(t *testing.T) {
	w := newWorld(t)
	resp, _ := w.do(http.MethodGet, "/users/by_telegram/12345", "evangelm:secret", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d", resp.StatusCode)
	}
}

func TestGetByTelegram_Success(t *testing.T) {
	w := newWorld(t)
	// Prime memstore directly.
	_, _ = w.st.Users().Upsert(context.Background(), store.User{
		TelegramID: 1, Nickname: "alice_s21",
		CampusID: "kazan-id", CampusName: "21 Kazan", CoalitionName: "Terra",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	resp, raw := w.do(http.MethodGet, "/users/by_telegram/1", "evangelm:secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var got api.User
	_ = json.Unmarshal(raw, &got)
	if got.TelegramID != 1 || got.Nickname != "alice_s21" {
		t.Errorf("got %+v", got)
	}
}

// ---------- PUT /users/by_telegram ----------

func TestPutByTelegram_LiveS21Lookup(t *testing.T) {
	w := newWorld(t)
	w.s21.SetUser("alice_s21", "anything", s21.Profile{
		Login: "alice_s21", CampusID: "kazan-id", CampusName: "21 Kazan",
	})
	resp, raw := w.do(http.MethodPut, "/users/by_telegram/100", "evangelm:secret", api.PutUserRequest{Nickname: "alice_s21"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var got api.User
	_ = json.Unmarshal(raw, &got)
	if got.TelegramID != 100 || got.Nickname != "alice_s21" || got.CampusName == "" {
		t.Errorf("got %+v", got)
	}
	// Cache should now be warm.
	if _, err := w.st.NicknameCache().Get(context.Background(), "alice_s21"); err != nil {
		t.Errorf("cache not warmed: %v", err)
	}
}

func TestPutByTelegram_NicknameNotInS21(t *testing.T) {
	w := newWorld(t)
	// Don't SetUser for "ghost", so S21 LookupByLogin returns ErrNotFound.
	resp, raw := w.do(http.MethodPut, "/users/by_telegram/100", "evangelm:secret", api.PutUserRequest{Nickname: "ghost"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "not found") {
		t.Errorf("body=%s", raw)
	}
}

func TestPutByTelegram_EmptyNickname(t *testing.T) {
	w := newWorld(t)
	resp, _ := w.do(http.MethodPut, "/users/by_telegram/100", "evangelm:secret", api.PutUserRequest{Nickname: "  "})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d", resp.StatusCode)
	}
}

func TestPutByTelegram_CacheHitAvoidsS21Call(t *testing.T) {
	w := newWorld(t)
	// Pre-populate cache: bot has previously seen "alice_s21".
	_ = w.st.NicknameCache().Upsert(context.Background(), store.NicknameCacheEntry{
		Nickname: "alice_s21", CampusID: "kazan-id", CampusName: "21 Kazan",
	})
	// Inject failure on LookupByLogin so we can verify the cache path doesn't hit S21.
	w.s21.FailNext("LookupByLogin", s21.ErrUnavailable)
	resp, raw := w.do(http.MethodPut, "/users/by_telegram/100", "evangelm:secret", api.PutUserRequest{Nickname: "alice_s21"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestPutByTelegram_TwoTelegramIDsShareOneNickname(t *testing.T) {
	w := newWorld(t)
	// "shared_nick" is the S21 login two different telegram_ids will both claim.
	w.s21.SetUser("shared_nick", "ignored", s21.Profile{
		Login: "shared_nick", CampusID: "kazan-id", CampusName: "21 Kazan",
	})
	// First claim.
	resp, raw := w.do(http.MethodPut, "/users/by_telegram/100", "evangelm:secret", api.PutUserRequest{Nickname: "shared_nick"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first claim failed: status=%d body=%s", resp.StatusCode, raw)
	}
	// Second telegram_id claims the same nickname.
	resp, raw = w.do(http.MethodPut, "/users/by_telegram/200", "evangelm:secret", api.PutUserRequest{Nickname: "shared_nick"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Q4: duplicates must be allowed; got status=%d body=%s", resp.StatusCode, raw)
	}
	// Listing by nickname now returns both, earliest first.
	resp, raw = w.do(http.MethodGet, "/users/by_nickname/shared_nick", "evangelm:secret", nil)
	var list api.ListResponse
	_ = json.Unmarshal(raw, &list)
	if len(list.Users) != 2 {
		t.Fatalf("expected 2, got %d (body=%s)", len(list.Users), raw)
	}
	if list.Users[0].TelegramID != 100 {
		t.Errorf("earliest should be telegram_id=100; got %d", list.Users[0].TelegramID)
	}
}

// ---------- DELETE /users/by_telegram ----------

func TestDeleteByTelegram(t *testing.T) {
	w := newWorld(t)
	_, _ = w.st.Users().Upsert(context.Background(), store.User{TelegramID: 1, Nickname: "x"})
	resp, _ := w.do(http.MethodDelete, "/users/by_telegram/1", "evangelm:secret", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status=%d", resp.StatusCode)
	}
	// Idempotent second call.
	resp, _ = w.do(http.MethodDelete, "/users/by_telegram/1", "evangelm:secret", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete should be 404; got %d", resp.StatusCode)
	}
}

// ---------- batch ----------

func TestLookupBatch(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	_, _ = w.st.Users().Upsert(ctx, store.User{TelegramID: 1, Nickname: "a"})
	_, _ = w.st.Users().Upsert(ctx, store.User{TelegramID: 3, Nickname: "c"})
	resp, raw := w.do(http.MethodPost, "/users/lookup_telegram_batch", "evangelm:secret",
		api.LookupTelegramBatchRequest{TelegramIDs: []int64{1, 2, 3, 4}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out api.LookupTelegramBatchResponse
	_ = json.Unmarshal(raw, &out)
	if len(out.Users) != 2 {
		t.Fatalf("expected 2 (missing telegram_ids silently dropped), got %d", len(out.Users))
	}
}

func TestLookupBatch_OverSize(t *testing.T) {
	w := newWorld(t)
	ids := make([]int64, 101)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	resp, raw := w.do(http.MethodPost, "/users/lookup_telegram_batch", "evangelm:secret",
		api.LookupTelegramBatchRequest{TelegramIDs: ids})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status=%d body=%s", resp.StatusCode, raw)
	}
}

// ---------- by_nickname ----------

func TestListByNickname_Empty(t *testing.T) {
	w := newWorld(t)
	resp, raw := w.do(http.MethodGet, "/users/by_nickname/noone", "evangelm:secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with empty list, got %d body=%s", resp.StatusCode, raw)
	}
	var out api.ListResponse
	_ = json.Unmarshal(raw, &out)
	if len(out.Users) != 0 {
		t.Errorf("expected empty users array, got %v", out.Users)
	}
}

// ---------- routing ----------

func TestRouting_UnknownPath(t *testing.T) {
	w := newWorld(t)
	resp, _ := w.do(http.MethodGet, "/whatever", "evangelm:secret", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d", resp.StatusCode)
	}
}

func TestRouting_WrongMethod(t *testing.T) {
	w := newWorld(t)
	resp, _ := w.do(http.MethodPatch, "/users/by_telegram/1", "evangelm:secret", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status=%d", resp.StatusCode)
	}
}

func TestHealth(t *testing.T) {
	w := newWorld(t)
	resp, raw := w.do(http.MethodGet, "/health", "", nil) // no auth
	if resp.StatusCode != http.StatusOK || string(raw) != "ok" {
		t.Errorf("health: %d %q", resp.StatusCode, raw)
	}
}

// TestAuth_TokenCacheSkipsS21OnHit: once a token has been validated, the
// next request bearing it must not call s21.Authenticate again. We prove
// it by populating the cache via one happy request, then poisoning the
// mock — a second request with the same token still has to succeed
// because the cache short-circuits.
func TestAuth_TokenCacheSkipsS21OnHit(t *testing.T) {
	w := newWorld(t)

	// First request: cache empty, mock is happy → success, cache populates.
	resp1, _ := w.do(http.MethodGet, "/users/by_telegram/123", "evangelm:secret", nil)
	// Anything except 401/403 (auth-related rejections) counts as "auth
	// passed". 404 on the user is fine — we only care that authenticate()
	// succeeded.
	if resp1.StatusCode == http.StatusUnauthorized || resp1.StatusCode == http.StatusForbidden {
		t.Fatalf("first request rejected at auth: %d", resp1.StatusCode)
	}
	if w.srv.S21Tokens.Size() != 1 {
		t.Errorf("expected 1 cache entry after first hit, got %d", w.srv.S21Tokens.Size())
	}

	// Poison the mock: the next Authenticate call would fail. A cache hit
	// must not reach the mock, so the request should still pass auth.
	w.s21.FailNext("Authenticate", errors.New("s21: blow up"))
	resp2, _ := w.do(http.MethodGet, "/users/by_telegram/123", "evangelm:secret", nil)
	if resp2.StatusCode == http.StatusUnauthorized || resp2.StatusCode == http.StatusForbidden {
		t.Errorf("cached token must skip S21; got auth rejection status=%d", resp2.StatusCode)
	}
}

// ---------- S1+S2: admin scope gating ----------

// newKeysWorld is `newWorld` with API key enforcement turned ON so the
// scope-check tests are exercising the real authorization path.
func newKeysWorld(t *testing.T) *world {
	w := newWorld(t)
	w.srv.EnforceAPIKey = true
	return w
}

// TestRevokeKey_UnscopedRequiresAdmin (S1): a write-scope key cannot
// revoke an arbitrary key by name without `?created_by=`. This is the
// core S1 vuln — pre-fix any write-scope caller could blast away
// operator-minted keys.
func TestRevokeKey_UnscopedRequiresAdmin(t *testing.T) {
	w := newKeysWorld(t)
	w.mintKey("victim", "read,write", 0) // operator-minted (CreatedBy = 0)
	attackerKey := w.mintKey("attacker", "read,write", 999)

	// Unscoped revoke (no ?created_by) must be rejected.
	resp, body := w.doWithKey(http.MethodDelete, "/admin/keys/victim", "evangelm:secret", attackerKey, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on unscoped revoke with write-only key; got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "admin scope") {
		t.Errorf("expected error message to mention admin scope; got %s", body)
	}

	// And the victim key must still be active.
	keys, err := w.st.APIKeys().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Name == "victim" && k.RevokedAt != nil {
			t.Errorf("victim key was revoked despite forbidden response")
		}
	}
}

// TestRevokeKey_AdminScopeCanRevokeAny (S1): with an admin-scope key,
// unscoped revoke succeeds.
func TestRevokeKey_AdminScopeCanRevokeAny(t *testing.T) {
	w := newKeysWorld(t)
	w.mintKey("victim", "read,write", 0)
	adminKey := w.mintKey("operator", "read,write,admin", 0)

	resp, body := w.doWithKey(http.MethodDelete, "/admin/keys/victim", "evangelm:secret", adminKey, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on admin-scope unscoped revoke; got %d body=%s", resp.StatusCode, body)
	}
}

// TestRevokeKey_ScopedRevokeStillWorksForOwner (S1): write-scope can
// still revoke OWN keys via ?created_by=. Here the key revokes itself —
// the simplest way to satisfy the "one active key per creator" rule the
// store enforces.
func TestRevokeKey_ScopedRevokeStillWorksForOwner(t *testing.T) {
	w := newKeysWorld(t)
	tid := int64(42)
	myKey := w.mintKey("mine", "read,write", tid)

	resp, body := w.doWithKey(http.MethodDelete, "/admin/keys/mine?created_by=42", "evangelm:secret", myKey, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on scoped self-revoke; got %d body=%s", resp.StatusCode, body)
	}
}

// TestRevokeKey_ScopedRevokeRejectsOthers (S1): write-scope cannot revoke
// someone else's key even with ?created_by= — RevokeByName matches the
// created_by filter atomically.
func TestRevokeKey_ScopedRevokeRejectsOthers(t *testing.T) {
	w := newKeysWorld(t)
	w.mintKey("victim", "read,write", 100)             // owner = 100
	attackerKey := w.mintKey("attacker", "read,write", 999) // owner = 999

	// Attacker passes ?created_by=999 (their own tid) — store can't match
	// "victim" because victim's creator is 100, not 999.
	resp, body := w.doWithKey(http.MethodDelete, "/admin/keys/victim?created_by=999",
		"evangelm:secret", attackerKey, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 on cross-user scoped revoke; got %d body=%s", resp.StatusCode, body)
	}
}

// TestCreateKey_RateLimit (S6): a user can't churn POST /admin/keys
// faster than keyCreateRateLimitMax per window. Direct coverage of the
// create-revoke-create-revoke abuse pattern. We authenticate the actor
// with an operator (admin-scope) key so the auth itself doesn't count
// against the per-user limit under test.
func TestCreateKey_RateLimit(t *testing.T) {
	w := newKeysWorld(t)
	tid := int64(7000)
	adminKey := w.mintKey("ops", "read,write,admin", 0)

	// Hammer create-revoke up to the limit. Each successful POST burns
	// one slot in the rate window.
	for i := 0; i < 10; i++ {
		body := map[string]any{
			"name":                   "k-" + strconv.Itoa(i),
			"scopes":                 "read,write",
			"created_by_telegram_id": tid,
		}
		resp, b := w.doWithKey(http.MethodPost, "/admin/keys", "evangelm:secret", adminKey, body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create #%d failed before limit: %d %s", i, resp.StatusCode, b)
		}
		// Revoke immediately so the next create isn't blocked by the
		// one-active-key rule.
		if err := w.st.APIKeys().RevokeByName(context.Background(),
			"k-"+strconv.Itoa(i), tid, w.srv.Now()); err != nil {
			t.Fatal(err)
		}
	}

	// 11th create must be rate-limited.
	body := map[string]any{
		"name":                   "k-overflow",
		"scopes":                 "read,write",
		"created_by_telegram_id": tid,
	}
	resp, b := w.doWithKey(http.MethodPost, "/admin/keys", "evangelm:secret", adminKey, body)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 on rate-limit; got %d body=%s", resp.StatusCode, b)
	}
	if !strings.Contains(string(b), "rate_limited") {
		t.Errorf("expected rate_limited code in body; got %s", b)
	}
}

// TestCreateKey_RateLimitExemptsOperator (S6): CLI / operator-minted keys
// (CreatedByTelegramID = 0) bypass the per-user rate limit.
func TestCreateKey_RateLimitExemptsOperator(t *testing.T) {
	w := newKeysWorld(t)
	adminKey := w.mintKey("ops", "read,write,admin", 0)

	// Create lots of operator-minted keys, revoking between each. The
	// rate limit should never trip because tid=0 is exempt.
	for i := 0; i < 15; i++ {
		name := "op-" + strconv.Itoa(i)
		body := map[string]any{
			"name":                   name,
			"scopes":                 "read",
			"created_by_telegram_id": 0,
		}
		resp, b := w.doWithKey(http.MethodPost, "/admin/keys", "evangelm:secret", adminKey, body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("operator create #%d unexpectedly failed: %d %s", i, resp.StatusCode, b)
		}
		// "creator has active key" rule does NOT apply when tid=0 (see
		// store: "creator has no active key (unless creator == 0)").
	}
}

// TestListKeys_UnfilteredRequiresAdmin (S2): write-scope can't enumerate
// all keys; admin-scope can.
func TestListKeys_UnfilteredRequiresAdmin(t *testing.T) {
	w := newKeysWorld(t)
	w.mintKey("operator", "read,write", 0)
	w.mintKey("alice", "read,write", 100)
	writeKey := w.mintKey("attacker", "read,write", 999)
	adminKey := w.mintKey("ops", "read,write,admin", 0)

	// Write-scope without filter → 403.
	resp, body := w.doWithKey(http.MethodGet, "/admin/keys", "evangelm:secret", writeKey, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 on unfiltered list with write-only key; got %d body=%s", resp.StatusCode, body)
	}

	// Write-scope WITH ?created_by=999 → 200, only own keys.
	resp, body = w.doWithKey(http.MethodGet, "/admin/keys?created_by=999", "evangelm:secret", writeKey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on scoped list; got %d body=%s", resp.StatusCode, body)
	}
	var got api.ListKeysResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range got.Keys {
		if k.CreatedByTelegramID != 999 {
			t.Errorf("scoped list leaked another user's key: %+v", k)
		}
	}

	// Admin-scope without filter → 200, ALL keys.
	resp, body = w.doWithKey(http.MethodGet, "/admin/keys", "evangelm:secret", adminKey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on admin-scope unfiltered list; got %d body=%s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Keys) < 4 {
		t.Errorf("expected admin list to include all 4 keys; got %d", len(got.Keys))
	}
}

// TestAuth_TokenCacheDoesNotCacheFailures: a bad password gets rejected
// every time, even on repeat — failures are never cached. We prove it by
// asserting the bad token has not been stored.
func TestAuth_TokenCacheDoesNotCacheFailures(t *testing.T) {
	w := newWorld(t)
	resp, _ := w.do(http.MethodGet, "/users/by_telegram/123", "evangelm:wrong", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad creds, got %d", resp.StatusCode)
	}
	if w.srv.S21Tokens.Size() != 0 {
		t.Errorf("expected zero cache entries after a failed auth, got %d", w.srv.S21Tokens.Size())
	}
}

// TestErrorResponse_DoesNotLeakInternalDetails: a transport-level error
// from S21 must NOT have its raw text echoed in the HTTP response body.
// Direct coverage of S4 (err.Error leak).
func TestErrorResponse_DoesNotLeakInternalDetails(t *testing.T) {
	w := newWorld(t)
	leakyMsg := "ydb: connection refused: leaky internal goroutine stack"
	w.s21.FailNext("Authenticate", errors.New(leakyMsg))
	resp, body := w.do(http.MethodGet, "/users/by_telegram/123", "evangelm:secret", nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on transport-level S21 error, got %d", resp.StatusCode)
	}
	if strings.Contains(string(body), leakyMsg) {
		t.Errorf("response leaks raw internal error: %s", body)
	}
	if strings.Contains(string(body), "ydb:") || strings.Contains(string(body), "goroutine") {
		t.Errorf("response leaks suspicious internal markers: %s", body)
	}
	// And the sanitized payload should be present so the operator still
	// has a stable surface to grep for.
	if !strings.Contains(string(body), "internal_error") {
		t.Errorf("expected sanitized error code in body: %s", body)
	}
}
