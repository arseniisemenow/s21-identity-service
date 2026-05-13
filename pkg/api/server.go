package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/s21"
	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/store"
)

// Server hosts the HTTP API. Construct with New, mount Routes onto any
// net/http handler, or call ServeHTTP directly.
type Server struct {
	Store store.Store
	S21   s21.Client
	Now   func() time.Time // injectable for tests

	// EnforceAPIKey gates X-Api-Key checking. When false (bootstrap mode),
	// missing/invalid keys are logged but requests still proceed. When true,
	// requests without a valid key get 401. Set from API_KEY_ENFORCE env.
	EnforceAPIKey bool

	// EnforceHTTPS gates the TLS check. When true (production), the server
	// rejects non-HTTPS requests. Disabled in tests via SetEnforceHTTPS.
	EnforceHTTPS bool
}

// New constructs a Server with both enforcement flags ON by default — the
// safer setting. Bootstrap-mode deploys override via EnforceAPIKey = false.
// Tests override EnforceHTTPS = false.
func New(st store.Store, s21c s21.Client) *Server {
	return &Server{
		Store:         st,
		S21:           s21c,
		Now:           time.Now,
		EnforceAPIKey: true,
		EnforceHTTPS:  true,
	}
}

// ServeHTTP dispatches to the right handler based on path and method. Kept
// dependency-free of any router library.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// HTTPS hard-fail first — runs before any auth so we never look at
	// secret headers on a non-TLS connection.
	if !s.requestIsTLS(r) {
		s.writeError(w, http.StatusUpgradeRequired, "https_required", "this endpoint is HTTPS-only")
		return
	}
	if r.URL.Path == "/health" {
		_, _ = w.Write([]byte("ok"))
		return
	}
	switch {
	case r.URL.Path == "/users/lookup_telegram_batch":
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
			return
		}
		s.handleLookupTelegramBatch(w, r)
		return
	case r.URL.Path == "/admin/keys":
		switch r.Method {
		case http.MethodPost:
			s.handleCreateKey(w, r)
		case http.MethodGet:
			s.handleListKeys(w, r)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		}
		return
	}
	// /users/by_telegram/{tid} — GET, PUT, DELETE
	if tid, ok := matchByTelegram(r.URL.Path); ok {
		switch r.Method {
		case http.MethodGet:
			s.handleGetByTelegram(w, r, tid)
		case http.MethodPut:
			s.handlePutByTelegram(w, r, tid)
		case http.MethodDelete:
			s.handleDeleteByTelegram(w, r, tid)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		}
		return
	}
	// /users/by_nickname/{nick} — GET
	if nick, ok := matchByNickname(r.URL.Path); ok {
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
			return
		}
		s.handleListByNickname(w, r, nick)
		return
	}
	// /admin/keys/{name} — DELETE (revoke)
	if name, ok := matchAdminKey(r.URL.Path); ok {
		if r.Method != http.MethodDelete {
			s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "DELETE required")
			return
		}
		s.handleRevokeKey(w, r, name)
		return
	}
	s.writeError(w, http.StatusNotFound, "not_found", "")
}

// requestIsTLS reports whether the request arrived over a secure channel.
// Direct connections have r.TLS != nil. Behind Yandex API Gateway (or any
// reverse proxy that terminates TLS) we look for X-Forwarded-Proto.
func (s *Server) requestIsTLS(r *http.Request) bool {
	if !s.EnforceHTTPS {
		return true
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

var (
	reByTelegram = regexp.MustCompile(`^/users/by_telegram/(\d+)$`)
	reByNickname = regexp.MustCompile(`^/users/by_nickname/([^/]+)$`)
	reAdminKey   = regexp.MustCompile(`^/admin/keys/([A-Za-z0-9_.-]+)$`)
)

func matchByTelegram(p string) (int64, bool) {
	m := reByTelegram.FindStringSubmatch(p)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func matchByNickname(p string) (string, bool) {
	m := reByNickname.FindStringSubmatch(p)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func matchAdminKey(p string) (string, bool) {
	m := reAdminKey.FindStringSubmatch(p)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ---------------- auth ----------------

// authenticate extracts the X-S21-Token header, parses it as "login:password",
// and validates the pair against S21 (with cache acceleration). Returns the
// resolved admin login on success.
func (s *Server) authenticate(ctx context.Context, r *http.Request) (string, error) {
	tok := r.Header.Get("X-S21-Token")
	if tok == "" {
		return "", errMissingToken
	}
	colon := strings.IndexByte(tok, ':')
	if colon <= 0 || colon == len(tok)-1 {
		return "", errMalformedToken
	}
	login, password := tok[:colon], tok[colon+1:]
	if _, err := s.S21.Authenticate(ctx, login, password); err != nil {
		if errors.Is(err, s21.ErrInvalidCredentials) {
			return "", errInvalidToken
		}
		return "", err
	}
	return login, nil
}

var (
	errMissingToken   = errors.New("missing X-S21-Token header")
	errMalformedToken = errors.New("X-S21-Token must be login:password")
	errInvalidToken   = errors.New("S21 rejected the supplied credentials")
	errMissingAPIKey  = errors.New("missing X-Api-Key header")
	errInvalidAPIKey  = errors.New("X-Api-Key is not recognized")
	errRevokedAPIKey  = errors.New("X-Api-Key has been revoked")
	errAPIKeyScope    = errors.New("X-Api-Key lacks the required scope")
)

// hashAPIKey returns the base64-stdencoded sha256 of a plaintext API key.
// The same encoding is used by the CLI when minting, so a row lookup is a
// straight equality match.
func hashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// generateAPIKey returns 32 random bytes, base64-stdencoded. The CLI and the
// /admin/keys POST handler both call this when minting.
func generateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// authenticateAPIKey extracts the X-Api-Key header, hashes it, looks up the
// stored row, and confirms it's active and carries `requiredScope`. Returns
// the matched APIKey on success. In dry-run mode (EnforceAPIKey == false)
// failures are logged but the call returns nil, nil — the caller proceeds
// without a key.
func (s *Server) authenticateAPIKey(ctx context.Context, r *http.Request, requiredScope string) (*store.APIKey, error) {
	plaintext := r.Header.Get("X-Api-Key")
	if plaintext == "" {
		if s.EnforceAPIKey {
			return nil, errMissingAPIKey
		}
		log.Printf("api_key: missing (dry-run mode) path=%s method=%s", r.URL.Path, r.Method)
		return nil, nil
	}
	got := hashAPIKey(plaintext)
	row, err := s.Store.APIKeys().GetByHash(ctx, got)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if s.EnforceAPIKey {
				return nil, errInvalidAPIKey
			}
			log.Printf("api_key: unknown (dry-run mode) path=%s method=%s", r.URL.Path, r.Method)
			return nil, nil
		}
		return nil, err
	}
	// Constant-time compare guards against hash-equality timing leaks
	// (paranoid; both sides are fixed-length sha256 outputs).
	if subtle.ConstantTimeCompare([]byte(row.KeyHash), []byte(got)) != 1 {
		if s.EnforceAPIKey {
			return nil, errInvalidAPIKey
		}
		return nil, nil
	}
	if !row.IsActive() {
		if s.EnforceAPIKey {
			return nil, errRevokedAPIKey
		}
		log.Printf("api_key: revoked (dry-run mode) name=%s", row.Name)
		return nil, nil
	}
	if requiredScope != "" && !row.HasScope(requiredScope) {
		if s.EnforceAPIKey {
			return nil, errAPIKeyScope
		}
		log.Printf("api_key: scope mismatch (dry-run mode) name=%s have=%s need=%s", row.Name, row.Scopes, requiredScope)
		return nil, nil
	}
	return &row, nil
}

// authorize runs the full request gate: HTTPS (already enforced upstream in
// ServeHTTP), API key (with scope), and S21 token. Returns the matched S21
// admin login on success — needed by handlePutByTelegram for downstream
// S21 calls. Writes the appropriate error response and returns ("", false)
// on failure; caller just returns after.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, requiredScope string) (string, bool) {
	if _, err := s.authenticateAPIKey(r.Context(), r, requiredScope); err != nil {
		s.writeAuthError(w, err)
		return "", false
	}
	adminLogin, err := s.authenticate(r.Context(), r)
	if err != nil {
		s.writeAuthError(w, err)
		return "", false
	}
	return adminLogin, true
}

// ---------------- handlers ----------------

func (s *Server) handleGetByTelegram(w http.ResponseWriter, r *http.Request, tid int64) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	row, err := s.Store.Users().GetByTelegramID(r.Context(), tid)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "not_found", "no nickname registered for telegram_id")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, userFromStore(row))
}

func (s *Server) handleLookupTelegramBatch(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	var req LookupTelegramBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}
	if len(req.TelegramIDs) > 100 {
		s.writeError(w, http.StatusBadRequest, "bad_request", "batch size capped at 100")
		return
	}
	rows, err := s.Store.Users().GetByTelegramIDs(r.Context(), req.TelegramIDs)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := LookupTelegramBatchResponse{Users: make([]User, 0, len(rows))}
	for _, r := range rows {
		out.Users = append(out.Users, userFromStore(r))
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListByNickname(w http.ResponseWriter, r *http.Request, nick string) {
	if _, ok := s.authorize(w, r, "read"); !ok {
		return
	}
	rows, err := s.Store.Users().ListByNickname(r.Context(), nick)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := ListResponse{Users: make([]User, 0, len(rows))}
	for _, r := range rows {
		out.Users = append(out.Users, userFromStore(r))
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutByTelegram(w http.ResponseWriter, r *http.Request, tid int64) {
	adminLogin, ok := s.authorize(w, r, "write")
	if !ok {
		return
	}
	var req PutUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}
	nick := strings.TrimSpace(req.Nickname)
	if nick == "" {
		s.writeError(w, http.StatusBadRequest, "bad_request", "nickname is required")
		return
	}

	// Resolve nickname → S21 profile (with cache acceleration).
	profile, err := s.resolveNickname(r.Context(), nick, adminLogin, r)
	if err != nil {
		if errors.Is(err, s21.ErrNotFound) {
			s.writeError(w, http.StatusBadRequest, "bad_request", "S21 nickname not found")
			return
		}
		if errors.Is(err, s21.ErrInvalidCredentials) {
			s.writeError(w, http.StatusUnauthorized, "invalid_token", "S21 rejected admin credentials")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	now := s.Now().UTC()
	row, err := s.Store.Users().Upsert(r.Context(), store.User{
		TelegramID:    tid,
		Nickname:      profile.Login,
		CampusID:      profile.CampusID,
		CampusName:    profile.CampusName,
		CoalitionName: profile.CoalitionName,
		CreatedAt:     now, // memstore preserves the existing CreatedAt on update
		UpdatedAt:     now,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, userFromStore(row))
}

func (s *Server) handleDeleteByTelegram(w http.ResponseWriter, r *http.Request, tid int64) {
	if _, ok := s.authorize(w, r, "write"); !ok {
		return
	}
	if err := s.Store.Users().Delete(r.Context(), tid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resolveNickname returns the S21 profile for `nick`, using the cache if hot
// and falling back to a live S21 LookupByLogin with the caller's admin creds.
// The header creds were already validated by authenticate(); we extract them
// again here.
func (s *Server) resolveNickname(ctx context.Context, nick, adminLogin string, r *http.Request) (s21.Profile, error) {
	// Cache hit.
	if e, err := s.Store.NicknameCache().Get(ctx, nick); err == nil {
		return s21.Profile{
			Login:         e.Nickname,
			CampusID:      e.CampusID,
			CampusName:    e.CampusName,
			CoalitionName: e.CoalitionName,
		}, nil
	}
	// Cache miss — re-parse the header (we know it's well-formed at this point).
	tok := r.Header.Get("X-S21-Token")
	colon := strings.IndexByte(tok, ':')
	_, password := tok[:colon], tok[colon+1:]
	prof, err := s.S21.LookupByLogin(ctx, adminLogin, password, nick)
	if err != nil {
		return s21.Profile{}, err
	}
	_ = s.Store.NicknameCache().Upsert(ctx, store.NicknameCacheEntry{
		Nickname:      prof.Login,
		CampusID:      prof.CampusID,
		CampusName:    prof.CampusName,
		CoalitionName: prof.CoalitionName,
		CachedAt:      s.Now().UTC(),
	})
	return prof, nil
}

// ---------------- helpers ----------------

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, ErrorBody{Code: code, Message: message})
}

func (s *Server) writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errMissingToken):
		s.writeError(w, http.StatusUnauthorized, "missing_token", err.Error())
	case errors.Is(err, errMalformedToken):
		s.writeError(w, http.StatusUnauthorized, "malformed_token", err.Error())
	case errors.Is(err, errInvalidToken):
		s.writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
	case errors.Is(err, errMissingAPIKey):
		s.writeError(w, http.StatusUnauthorized, "missing_api_key", err.Error())
	case errors.Is(err, errInvalidAPIKey):
		s.writeError(w, http.StatusUnauthorized, "invalid_api_key", err.Error())
	case errors.Is(err, errRevokedAPIKey):
		s.writeError(w, http.StatusUnauthorized, "revoked_api_key", err.Error())
	case errors.Is(err, errAPIKeyScope):
		s.writeError(w, http.StatusForbidden, "scope", err.Error())
	default:
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}

func userFromStore(u store.User) User {
	return User{
		TelegramID:    u.TelegramID,
		Nickname:      u.Nickname,
		CampusID:      u.CampusID,
		CampusName:    u.CampusName,
		CoalitionName: u.CoalitionName,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

// ---------------- /admin/keys handlers ----------------

// validKeyName enforces the same character set as the URL regex so a freshly-
// minted key can be revoked through DELETE /admin/keys/<name>.
var validKeyName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// allowedScopes is the universe of acceptable scopes strings on a single key.
// We canonicalise to one of these to keep the storage shape predictable and
// the middleware check trivial (HasScope("read") vs HasScope("write")).
var allowedScopes = map[string]string{
	"read":       "read",
	"write":      "read,write", // write implies read
	"read,write": "read,write",
	"write,read": "read,write",
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "write"); !ok {
		return
	}
	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validKeyName.MatchString(name) {
		s.writeError(w, http.StatusBadRequest, "bad_request", "name must be 1–64 chars, letters/digits/_.- only")
		return
	}
	canonScopes, scopesOK := allowedScopes[strings.TrimSpace(req.Scopes)]
	if !scopesOK {
		s.writeError(w, http.StatusBadRequest, "bad_request", "scopes must be one of: read, write, read,write")
		return
	}
	plaintext, err := generateAPIKey()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	row := store.APIKey{
		KeyHash:             hashAPIKey(plaintext),
		Name:                name,
		Scopes:              canonScopes,
		CreatedAt:           s.Now().UTC(),
		CreatedByTelegramID: req.CreatedByTelegramID,
	}
	if err := s.Store.APIKeys().Insert(r.Context(), row); err != nil {
		switch {
		case errors.Is(err, store.ErrKeyNameInUse):
			s.writeError(w, http.StatusConflict, "name_in_use", "an active key with that name already exists")
		case errors.Is(err, store.ErrCreatorHasActiveKey):
			s.writeError(w, http.StatusConflict, "creator_has_key", "this user already has an active key; revoke first")
		default:
			s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		}
		return
	}
	s.writeJSON(w, http.StatusCreated, CreateKeyResponse{
		Key:       plaintext,
		Name:      row.Name,
		Scopes:    row.Scopes,
		CreatedAt: row.CreatedAt,
	})
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request, name string) {
	if _, ok := s.authorize(w, r, "write"); !ok {
		return
	}
	// Optional ?created_by=<telegram_id> filter — the bot uses this so a user
	// can only revoke keys they themselves created. CLI omits it.
	var by int64
	if v := r.URL.Query().Get("created_by"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "created_by must be integer")
			return
		}
		by = parsed
	}
	err := s.Store.APIKeys().RevokeByName(r.Context(), name, by, s.Now().UTC())
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "not_found", "no active key with that name (or not yours)")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r, "write"); !ok {
		return
	}
	rows, err := s.Store.APIKeys().List(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := ListKeysResponse{Keys: make([]APIKeyInfo, 0, len(rows))}
	for _, k := range rows {
		out.Keys = append(out.Keys, APIKeyInfo{
			Name:                k.Name,
			Scopes:              k.Scopes,
			CreatedAt:           k.CreatedAt,
			RevokedAt:           k.RevokedAt,
			CreatedByTelegramID: k.CreatedByTelegramID,
		})
	}
	s.writeJSON(w, http.StatusOK, out)
}
