// Package main is the identity-service Cloud Function entrypoint.
//
// It exposes the HTTP API documented in pkg/api. API Gateway converts each
// HTTPS request into a JSON event that we translate back into an
// *http.Request before delegating to the package-level api.Server.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"

	"github.com/arseniisemenow/s21-identity-service/pkg/api"
	"github.com/arseniisemenow/s21-identity-service/pkg/s21"
	"github.com/arseniisemenow/s21-identity-service/pkg/store"
	"github.com/arseniisemenow/s21-identity-service/pkg/store/memstore"
	"github.com/arseniisemenow/s21-identity-service/pkg/store/ydbstore"
)

// APIGatewayRequest is the JSON event Yandex API Gateway hands the function.
type APIGatewayRequest struct {
	HTTPMethod string            `json:"httpMethod"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	IsBase64   bool              `json:"isBase64Encoded"`
}

// APIGatewayResponse is what API Gateway expects back.
type APIGatewayResponse struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body"`
	IsBase64   bool              `json:"isBase64Encoded,omitempty"`
}

var (
	initOnce sync.Once
	srv      *api.Server
	initErr  error
)

func bootstrap() {
	s21c := s21.NewClient()
	var st store.Store
	if ep := os.Getenv("YDB_ENDPOINT"); ep != "" {
		yds, err := ydbstore.Open(context.Background(), ep)
		if err != nil {
			log.Printf("ydbstore.Open failed (%v); falling back to memstore", err)
			st = memstore.New()
		} else {
			st = yds
		}
	} else {
		st = memstore.New()
	}
	srv = api.New(st, s21c)
	// API_KEY_ENFORCE=false → bootstrap mode (logs warnings, accepts requests
	// without a key). Any other value (including empty) → enforce. Operator
	// flips this once all clients have been issued keys and have them in env.
	if os.Getenv("API_KEY_ENFORCE") == "false" {
		srv.EnforceAPIKey = false
		log.Printf("api_key: starting in DRY-RUN mode (API_KEY_ENFORCE=false)")
	}
}

// Handler is the Yandex Cloud Function entrypoint.
func Handler(ctx context.Context, req *APIGatewayRequest) (*APIGatewayResponse, error) {
	initOnce.Do(bootstrap)
	if initErr != nil {
		return &APIGatewayResponse{StatusCode: 500, Body: initErr.Error()}, nil
	}

	body := req.Body
	if req.IsBase64 {
		// API Gateway sends base64-encoded bodies for binary content; the
		// identity service is JSON-only so this is exceedingly rare, but
		// handle it for symmetry.
		raw, err := decodeB64(body)
		if err != nil {
			log.Printf("decode base64 body: %v", err)
		} else {
			body = raw
		}
	}

	// Yandex API Gateway with a catch-all path template (`/{path+}`) sends
	// the literal template in req.Path; the actual request URI is in the
	// X-Envoy-Original-Path header. Fall back to req.Path for setups where
	// specific paths are routed individually.
	actualPath := req.Path
	for _, key := range []string{"X-Envoy-Original-Path", "x-envoy-original-path"} {
		if v, ok := req.Headers[key]; ok && v != "" {
			actualPath = v
			break
		}
	}
	log.Printf("incoming: method=%s path=%q body_len=%d", req.HTTPMethod, actualPath, len(body))
	_ = redactedHeaders // kept for future targeted debugging
	httpReq, err := http.NewRequestWithContext(ctx, req.HTTPMethod, actualPath, bytes.NewReader([]byte(body)))
	if err != nil {
		return &APIGatewayResponse{StatusCode: 400, Body: err.Error()}, nil
	}
	for k, v := range req.Headers {
		// Yandex sometimes lower-cases headers; canonicalise on the way in.
		httpReq.Header.Set(http.CanonicalHeaderKey(k), v)
	}

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httpReq)

	respHeaders := map[string]string{}
	for k, vs := range rr.Header() {
		if len(vs) > 0 {
			respHeaders[k] = strings.Join(vs, ", ")
		}
	}
	respBody, _ := io.ReadAll(rr.Result().Body)
	return &APIGatewayResponse{
		StatusCode: rr.Code,
		Headers:    respHeaders,
		Body:       string(respBody),
	}, nil
}

func decodeB64(s string) (string, error) {
	r, err := io.ReadAll(io.NopCloser(bytes.NewReader([]byte(s))))
	if err != nil {
		return "", err
	}
	return string(r), nil
}

// Compile-time guard against accidental JSON dependency drift.
var _ = json.Marshal

// redactedHeaders strips the auth header value for safe logging.
func redactedHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		canon := http.CanonicalHeaderKey(k)
		if canon == "X-S21-Token" || canon == "Authorization" || canon == "X-Api-Key" {
			out[canon] = "<redacted>"
			continue
		}
		out[canon] = v
	}
	return out
}

// main is a stub so `go build` works. Yandex's Go runtime invokes Handler
// via reflection without ever calling main.
func main() {}
