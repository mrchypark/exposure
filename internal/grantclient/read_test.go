package grantclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
)

var grantRequest = contracts.ReadGrantRequest{ExposureID: "e", ExposureVersion: 1, ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ResourceID: "r", RequestBinding: "b"}

func TestReadUsesFixedWireAndHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/exposure-authz/read" || r.Header.Get("Authorization") != "Bearer user" || r.Header.Get("X-Organization-ID") != "org" || r.Header.Get("X-Grant-App-Auth-Key") != "app" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		b, _ := io.ReadAll(r.Body)
		want := `{"exposureId":"e","exposureVersion":1,"artifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","requestBinding":"b"}`
		if string(b) != want {
			t.Fatalf("body=%s", b)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true,"reason":"ok","exposureId":"e","exposureVersion":1,"artifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","requestBinding":"b","principalDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","issuedAt":"2025-01-01T00:00:00Z","expiresAt":"2030-01-01T00:00:00Z"}`))
	}))
	defer server.Close()
	c := New(server.URL, server.Client(), time.Second, 4096)
	_, err := c.Read(context.Background(), grantRequest, "Bearer user", "org", "app")
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadMapsGrantStatusWithoutParsingOrLeakingLegacyBody(t *testing.T) {
	const secret = "private-grant-error-detail"
	for _, tc := range []struct {
		status int
		code   string
	}{
		{http.StatusUnauthorized, "unauthenticated"},
		{http.StatusForbidden, "access_denied"},
		{http.StatusServiceUnavailable, "upstream_failure"},
		{http.StatusBadGateway, "upstream_failure"},
		{http.StatusBadRequest, "invalid_request"},
		{http.StatusUnprocessableEntity, "invalid_request"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"error":"`+secret+`"}`+strings.Repeat("x", 8192))
			}))
			defer server.Close()
			_, err := New(server.URL, server.Client(), time.Second, 64).Read(context.Background(), grantRequest, "Bearer user", "org", "app")
			code, ok := dependency.ErrorCode(err)
			if !ok || code != tc.code || strings.Contains(err.Error(), secret) {
				t.Fatalf("status=%d code=%q ok=%v err=%v", tc.status, code, ok, err)
			}
		})
	}
}

func TestReadReturnsGrantStatusBeforeSlowLegacyBody(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		w.WriteHeader(http.StatusUnauthorized)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer cannot flush")
			return
		}
		_, _ = io.WriteString(w, `{"error":"private-partial`)
		flusher.Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	start := time.Now()
	_, err := New(server.URL, server.Client(), 2*time.Second, 64).Read(context.Background(), grantRequest, "Bearer user", "org", "app")
	if code, ok := dependency.ErrorCode(err); !ok || code != "unauthenticated" || time.Since(start) > 500*time.Millisecond || strings.Contains(err.Error(), "private-partial") {
		t.Fatalf("error=%v elapsed=%v", err, time.Since(start))
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Grant handler did not observe closed response body")
	}
}

func TestReadKeepsStrictDecisionSchemaOnSuccess(t *testing.T) {
	for _, body := range []string{
		`{"allowed":true}`,
		`{"allowed":true,"legacy":"ignored"}`,
		`{"error":"legacy-success-body"}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}))
		_, err := New(server.URL, server.Client(), time.Second, 4096).Read(context.Background(), grantRequest, "Bearer user", "org", "app")
		server.Close()
		if err == nil || strings.Contains(err.Error(), "legacy-success-body") {
			t.Fatalf("body=%s err=%v", body, err)
		}
	}
}
