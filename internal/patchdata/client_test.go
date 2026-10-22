package patchdata

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/dependency"
)

const plantID = "4n5mdid6ccx1bh6"

func newTestClient(base string, client *http.Client, timeout time.Duration, maxResponseBytes int64) *Client {
	c, err := New(base, client, timeout, maxResponseBytes, "service-token")
	if err != nil {
		panic(err)
	}
	return c
}

func TestClientUsesConfiguredOrigin(t *testing.T) {
	const base = "http://patch-data.example.svc.cluster.local:8090"
	client, err := New(base, http.DefaultClient, time.Second, 4096, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	if client.base != base {
		t.Fatalf("base=%q", client.base)
	}
}

func TestReadPlantUsesOnlyFixedPrivateOperationAndServiceBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != plantPath+plantID || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			t.Fatalf("request=%s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if got := r.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer service-token" {
			t.Fatalf("authorization=%q", got)
		}
		if r.Header.Get("X-Organization-ID") != "" || r.Header.Get("X-Grant-App-Auth-Key") != "" {
			t.Fatal("Grant-only headers leaked to Patch Data")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"id":"`+plantID+`","name":"Gwangdeok","updated":"2026-08-11 01:02:03.456Z"}`)
	}))
	defer server.Close()

	out, err := newTestClient(server.URL, server.Client(), time.Second, 4096).ReadPlant(context.Background(), plantID)
	if err != nil {
		t.Fatal(err)
	}
	if out.ResourceID != plantID || out.ResourceVersion != nil || out.SourceRevision != "2026-08-11 01:02:03.456Z" || len(out.RawResource) != 3 || out.RawResource["name"] != "Gwangdeok" {
		t.Fatalf("result=%#v", out)
	}
	for _, forbidden := range []string{"metadata", "organization", "permission", "collectionId", "collectionName"} {
		if _, leaked := out.RawResource[forbidden]; leaked {
			t.Fatalf("%s leaked", forbidden)
		}
	}
}

func TestReadPlantMapsStatusWithoutLeakingRemoteBody(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
	}{
		{http.StatusUnauthorized, "access_denied"},
		{http.StatusForbidden, "access_denied"},
		{http.StatusNotFound, "not_found"},
		{http.StatusBadRequest, "upstream_failure"},
		{http.StatusInternalServerError, "upstream_failure"},
		{http.StatusFound, "upstream_failure"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			targetCalled := false
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalled = true }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status == http.StatusFound {
					http.Redirect(w, r, target.URL, tc.status)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"message":"private remote detail"}`)
			}))
			defer server.Close()
			_, err := newTestClient(server.URL, server.Client(), time.Second, 4096).ReadPlant(context.Background(), plantID)
			code, ok := dependency.ErrorCode(err)
			if !ok || code != tc.code || targetCalled || strings.Contains(err.Error(), "private remote detail") {
				t.Fatalf("code=%q ok=%v target=%v err=%v", code, ok, targetCalled, err)
			}
		})
	}
}

func TestReadPlantRejectsMalformedOrUnboundedSuccess(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		max         int64
	}{
		{"content type", "text/plain", `{}`, 4096},
		{"duplicate", "application/json", `{"id":"` + plantID + `","id":"` + plantID + `","name":"x","updated":"2026-08-11T01:02:03Z"}`, 4096},
		{"wrong id", "application/json", `{"id":"aaaaaaaaaaaaaaa","name":"x","updated":"2026-08-11T01:02:03Z"}`, 4096},
		{"empty revision", "application/json", `{"id":"` + plantID + `","name":"x","updated":""}`, 4096},
		{"missing name", "application/json", `{"id":"` + plantID + `","updated":"2026-08-11T01:02:03Z"}`, 4096},
		{"null name", "application/json", `{"id":"` + plantID + `","name":null,"updated":"2026-08-11T01:02:03Z"}`, 4096},
		{"wrong type", "application/json", `{"id":"` + plantID + `","name":{},"updated":"2026-08-11T01:02:03Z"}`, 4096},
		{"extra field", "application/json", `{"id":"` + plantID + `","name":"x","updated":"2026-08-11T01:02:03Z","organization":"must-not-be-accepted"}`, 4096},
		{"oversize", "application/json", `{"id":"` + plantID + `","name":"long","updated":"2026-08-11T01:02:03Z"}`, 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			_, err := newTestClient(server.URL, server.Client(), time.Second, tc.max).ReadPlant(context.Background(), plantID)
			if code, ok := dependency.ErrorCode(err); !ok || code != "malformed_response" {
				t.Fatalf("error=%v code=%q", err, code)
			}
		})
	}
}

func TestReadPlantPromptlyRejectsChunkedOversizedSuccessWithoutLeak(t *testing.T) {
	const secret = "must-not-leak-streamed-secret"
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(handlerDone)
		w.Header().Set("Content-Type", "application/json")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer does not support flush")
			return
		}
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 1024; i++ {
			if _, err := io.WriteString(w, secret); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer server.Close()

	start := time.Now()
	out, err := newTestClient(server.URL, server.Client(), 2*time.Second, 64).ReadPlant(context.Background(), plantID)
	elapsed := time.Since(start)
	code, ok := dependency.ErrorCode(err)
	if !ok || code != "malformed_response" || elapsed > time.Second || out.ResourceID != "" || out.RawResource != nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("code=%q ok=%v elapsed=%v out=%#v err=%v", code, ok, elapsed, out, err)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("streaming handler did not stop after bounded client close")
	}
}

func TestReadPlantPreservesStatusWithOversizedErrorBody(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
	}{{http.StatusUnauthorized, "access_denied"}, {http.StatusForbidden, "access_denied"}, {http.StatusNotFound, "not_found"}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, strings.Repeat("private", 2048))
		}))
		_, err := newTestClient(server.URL, server.Client(), time.Second, 8).ReadPlant(context.Background(), plantID)
		server.Close()
		if code, ok := dependency.ErrorCode(err); !ok || code != tc.code {
			t.Fatalf("status=%d error=%v code=%q", tc.status, err, code)
		}
	}
}

func TestReadPlantTreatsUpdatedAsOpaqueRevision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"`+plantID+`","name":"x","updated":"opaque-revision-v1"}`)
	}))
	defer server.Close()
	out, err := newTestClient(server.URL, server.Client(), time.Second, 4096).ReadPlant(context.Background(), plantID)
	if err != nil || out.SourceRevision != "opaque-revision-v1" {
		t.Fatalf("result=%#v error=%v", out, err)
	}
}

func TestReadPlantBoundsTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	start := time.Now()
	_, err := newTestClient(server.URL, server.Client(), 20*time.Millisecond, 4096).ReadPlant(context.Background(), plantID)
	if code, ok := dependency.ErrorCode(err); !ok || code != "upstream_failure" || time.Since(start) > time.Second {
		t.Fatalf("error=%v elapsed=%v", err, time.Since(start))
	}
}

func TestReadPlantRejectsInvalidInputWithoutHTTP(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	client := newTestClient(server.URL, server.Client(), time.Second, 4096)
	if _, err := client.ReadPlant(context.Background(), "short"); err == nil || calls != 0 {
		t.Fatalf("error=%v calls=%d", err, calls)
	}
}

func TestClientRejectsInvalidServiceToken(t *testing.T) {
	for _, token := range []string{"", "Bearer nested", "has space", "line\nbreak", "==="} {
		if _, err := newClient("http://127.0.0.1", http.DefaultClient, time.Second, 4096, token); err == nil {
			t.Fatalf("token shape accepted: %q", token)
		}
	}
}
