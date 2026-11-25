package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/capability"
	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/contracts"
)

func TestStreamHealthIsListenerLivenessOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream *capability.StreamServer
		want   int
	}{
		{"disabled", nil, http.StatusNotFound},
		{"not listening", &capability.StreamServer{}, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			proxyAdmin(nil, nil, tc.stream).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stream-healthz", nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestLoadReadArtifactsCollection(t *testing.T) {
	d := t.TempDir()
	if _, err := loadReadArtifacts(filepath.Join(d, "none")); err == nil {
		t.Fatal("unreadable accepted")
	}
	for _, body := range []string{"[]", "[", "[{},{}]"} {
		path := filepath.Join(d, "bad.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadReadArtifacts(path); err == nil {
			t.Fatal("accepted", body)
		}
	}
	schema := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digest, err := contracts.Digest(map[string]any{"artifactType": "exposure.read.v1", "exposureId": "exp", "exposureVersion": float64(1), "source": map[string]any{"namespace": "ns", "objectType": "o", "schemaDigest": schema}, "projectionPointers": []string{"/x"}})
	if err != nil {
		t.Fatal(err)
	}
	artifact := fmt.Sprintf(`{"artifactType":"exposure.read.v1","exposureId":"exp","exposureVersion":1,"artifactDigest":"%s","source":{"namespace":"ns","objectType":"o","schemaDigest":"%s"},"projectionPointers":["/x"]}`, digest, schema)
	path := filepath.Join(d, "good.json")
	if err = os.WriteFile(path, []byte("["+artifact+"]"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadReadArtifacts(path); err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	if err = os.WriteFile(path, []byte("["+artifact+","+artifact+"]"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReadArtifacts(path); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestRuntimeClientsDisableEnvironmentProxyAndKeepDefaultTLSVerification(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	for name, c := range map[string]*http.Client{
		"read":       internalHTTPClient(config.Config{DependencyTimeout: time.Second}),
		"capability": proxyHTTPClient(config.Config{DependencyTimeout: time.Second}),
	} {
		defer c.CloseIdleConnections()
		transport, ok := c.Transport.(*http.Transport)
		if !ok || transport.Proxy != nil || transport.TLSClientConfig != nil {
			t.Fatalf("%s transport=%#v", name, c.Transport)
		}
	}
}

func TestGrantClientsRejectUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS reached handler")
	}))
	defer server.Close()
	for name, client := range map[string]*http.Client{
		"read":       internalHTTPClient(config.Config{DependencyTimeout: time.Second}),
		"capability": proxyHTTPClient(config.Config{DependencyTimeout: time.Second}),
	} {
		t.Run(name, func(t *testing.T) {
			defer client.CloseIdleConnections()
			if response, err := client.Get(server.URL); err == nil {
				response.Body.Close()
				t.Fatal("untrusted Grant certificate accepted")
			}
		})
	}
}

func TestRuntimeClientsDoNotFollowRedirects(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	for name, c := range map[string]*http.Client{
		"read":       internalHTTPClient(config.Config{DependencyTimeout: time.Second}),
		"capability": proxyHTTPClient(config.Config{DependencyTimeout: time.Second}),
	} {
		defer c.CloseIdleConnections()
		response, err := c.Get(source.URL)
		if err != nil {
			t.Fatal(name, err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusFound {
			t.Fatalf("%s status=%d", name, response.StatusCode)
		}
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect target called")
	}
}
