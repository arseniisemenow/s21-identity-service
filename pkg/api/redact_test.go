package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestRedactHeaders_ScrubsSensitive(t *testing.T) {
	h := http.Header{
		"X-S21-Token":  []string{"evangelm:hunter2"},
		"X-Api-Key":    []string{"sk-deadbeef"},
		"Authorization": []string{"Bearer xyz"},
		"Cookie":       []string{"session=abc"},
		// Non-sensitive — must pass through.
		"Content-Type": []string{"application/json"},
		"User-Agent":   []string{"curl/7.0"},
	}
	got := RedactHeaders(h)

	for _, name := range []string{"X-S21-Token", "X-Api-Key", "Authorization", "Cookie"} {
		if got.Get(name) != "[REDACTED]" {
			t.Errorf("expected %s redacted, got %q", name, got.Get(name))
		}
	}
	for _, name := range []string{"Content-Type", "User-Agent"} {
		if got.Get(name) == "[REDACTED]" {
			t.Errorf("non-sensitive header %s was redacted", name)
		}
	}
}

// TestRedactHeaders_NoMutation: the original Header map must not be
// modified — callers may still need the real values for their actual
// handler work.
func TestRedactHeaders_NoMutation(t *testing.T) {
	h := http.Header{
		"X-S21-Token": []string{"alice:pw"},
	}
	_ = RedactHeaders(h)
	if h.Get("X-S21-Token") != "alice:pw" {
		t.Errorf("RedactHeaders mutated original; got %q", h.Get("X-S21-Token"))
	}
}

// TestRedactHeaders_CaseInsensitive: header names canonicalised by
// net/http arrive as e.g. "X-S21-Token". A caller passing in odd casing
// (a future external middleware that doesn't canonicalise?) should still
// trigger redaction. We inspect the output map directly here because
// http.Header.Get canonicalises before lookup, masking the bug.
func TestRedactHeaders_CaseInsensitive(t *testing.T) {
	h := http.Header{
		"x-s21-TOKEN": []string{"alice:pw"},
	}
	got := RedactHeaders(h)
	v, ok := got["x-s21-TOKEN"]
	if !ok {
		t.Fatalf("expected key %q in output", "x-s21-TOKEN")
	}
	if !strings.Contains(strings.Join(v, ","), "REDACTED") {
		t.Errorf("expected redacted, got %v", v)
	}
}

// TestRedactHeaders_NilSafe: passing nil should not panic.
func TestRedactHeaders_NilSafe(t *testing.T) {
	if got := RedactHeaders(nil); got != nil {
		t.Errorf("RedactHeaders(nil) = %v; want nil", got)
	}
}
