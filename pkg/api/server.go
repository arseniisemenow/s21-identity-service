package api

import (
	"context"
	"encoding/json"
	"errors"
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
}

// New constructs a Server.
func New(st store.Store, s21c s21.Client) *Server {
	return &Server{Store: st, S21: s21c, Now: time.Now}
}

// ServeHTTP dispatches to the right handler based on path and method. Kept
// dependency-free of any router library.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/users/lookup_telegram_batch":
		if r.Method != http.MethodPost {
			s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
			return
		}
		s.handleLookupTelegramBatch(w, r)
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
	if r.URL.Path == "/health" {
		_, _ = w.Write([]byte("ok"))
		return
	}
	s.writeError(w, http.StatusNotFound, "not_found", "")
}

var (
	reByTelegram = regexp.MustCompile(`^/users/by_telegram/(\d+)$`)
	reByNickname = regexp.MustCompile(`^/users/by_nickname/([^/]+)$`)
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
)

// ---------------- handlers ----------------

func (s *Server) handleGetByTelegram(w http.ResponseWriter, r *http.Request, tid int64) {
	if _, err := s.authenticate(r.Context(), r); err != nil {
		s.writeAuthError(w, err)
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
	if _, err := s.authenticate(r.Context(), r); err != nil {
		s.writeAuthError(w, err)
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
	if _, err := s.authenticate(r.Context(), r); err != nil {
		s.writeAuthError(w, err)
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
	adminLogin, err := s.authenticate(r.Context(), r)
	if err != nil {
		s.writeAuthError(w, err)
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
	if _, err := s.authenticate(r.Context(), r); err != nil {
		s.writeAuthError(w, err)
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
