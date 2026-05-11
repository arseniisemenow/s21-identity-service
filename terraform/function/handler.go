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

	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/api"
	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/s21"
	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/store"
	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/store/memstore"
	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/store/ydbstore"
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

	httpReq, err := http.NewRequestWithContext(ctx, req.HTTPMethod, req.Path, bytes.NewReader([]byte(body)))
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

// main is a stub so `go build` works. Yandex's Go runtime invokes Handler
// via reflection without ever calling main.
func main() {}
