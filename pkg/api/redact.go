package api

import (
	"net/http"
	"strings"
)

// sensitiveHeaderNames lists HTTP headers that carry secrets in this
// service. RedactHeaders replaces their values with "[REDACTED]" before
// any log line would have a chance to dump them. The match is case-
// insensitive — Go's net/http canonicalises header names but external
// loggers / middleware might not.
var sensitiveHeaderNames = map[string]struct{}{
	"x-s21-token":   {},
	"x-api-key":     {},
	"authorization": {}, // not used today, but defensive against future code
	"cookie":        {}, // ditto
}

// RedactHeaders returns a shallow copy of h with values of sensitive
// headers replaced by "[REDACTED]". The original h is not mutated.
//
// Use this whenever you log an http.Header — directly or via fmt.Sprintf
// templates that might print one. Even if no current log line dumps
// headers, hauling all log statements through this helper keeps the
// surface small for future contributors who add a "log the request"
// debug aid.
func RedactHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		if isSensitiveHeader(k) {
			out[k] = []string{"[REDACTED]"}
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func isSensitiveHeader(name string) bool {
	_, ok := sensitiveHeaderNames[strings.ToLower(name)]
	return ok
}
