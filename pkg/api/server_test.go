package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
