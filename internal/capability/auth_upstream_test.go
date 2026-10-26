package capability

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

func TestGenericAuthUpstreamUsesPinnedCatalogWithoutDecision(t *testing.T) {
	const loginPath = "/identity/password-login"
	const good = `{ "identity": "user", "password": "correct" }`
	const bad = `{"identity":"user","password":"wrong"}`
	var upstreamCalls, catalogCalls, decisionCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		b, err := io.ReadAll(r.Body)
		if err != nil || r.Method != "POST" || r.URL.Path != loginPath || r.Header.Get("Content-Type") != "application/json" {
			t.Error("login transport changed")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Grant-App-Auth-Key") != "" {
			t.Error("login received a credential header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if string(b) == good {
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{ "token": "native-token", "user": {"id":"user"} }`)
		} else {
			if string(b) != bad {
				t.Error("login body changed")
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"code":400,"message":"native invalid credentials"}`)
		}
	}))
	defer upstream.Close()
	cap := capability{CapabilityID: "password-login", Version: 1, Enabled: true, AccessMode: "public_authn", Method: "POST", PathTemplate: loginPath, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "json", MaxBytes: 512, ForwardHeaders: []string{"Content-Type"}}, Response: responsePolicy{MaxBytes: 1024, Redirects: "deny", ErrorStatuses: []int{400}, ForwardHeaders: []string{"Content-Type", "Cache-Control"}}}
	cap.ContractDigest = capabilityDigest(cap)
	cat := catalog{SchemaVersion: 1, ProviderID: "arbitrary-auth-service", PepClientID: "auth-pep", Generation: 1, Capabilities: []capability{cap}, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
	cat.CatalogDigest = catalogDigest(&cat)
	grant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/catalog/arbitrary-auth-service" {
			catalogCalls.Add(1)
			if r.Header.Get("X-Grant-App-Auth-Key") != "catalog-key" {
				t.Error("missing catalog credential")
			}
			_ = json.NewEncoder(w).Encode(cat)
			return
		}
		decisionCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer grant.Close()
	cfg := config.ProxyConfig{AuthorizationMode: "forward-user", ProviderID: cat.ProviderID, PepClientID: cat.PepClientID, Origin: upstream.URL, AppAuthKey: "catalog-key", ExpectedCatalogDigest: cat.CatalogDigest, MaxRequestBytes: 512, MaxResponseBytes: 1024, AuthnLimiterKey: "limiter", PublicAuthnGlobalCapacity: 32, PublicAuthnPeerCapacity: 32, PublicAuthnGlobalRefill: time.Hour, PublicAuthnPeerRefill: time.Hour}
	p, err := New(cfg, grant.URL, upstream.Client(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body     string
		status   int
		response string
	}{
		{good, 201, `{ "token": "native-token", "user": {"id":"user"} }`},
		{bad, 400, `{"code":400,"message":"native invalid credentials"}`},
	} {
		req := httptest.NewRequest("POST", loginPath, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		p.Handler().ServeHTTP(out, req)
		if out.Code != tc.status || out.Body.String() != tc.response || out.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("native login response changed: status=%d cache=%q", out.Code, out.Header().Get("Cache-Control"))
		}
	}
	for _, tc := range []struct{ header, value, body string }{
		{"Authorization", "Bearer injected", good},
		{"Cookie", "session=injected", good},
		{"", "", `{"password":"` + strings.Repeat("x", 513) + `"}`},
	} {
		req := httptest.NewRequest("POST", loginPath, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		if tc.header != "" {
			req.Header.Set(tc.header, tc.value)
		}
		out := httptest.NewRecorder()
		p.Handler().ServeHTTP(out, req)
		if out.Code != 422 {
			t.Fatalf("invalid login status=%d", out.Code)
		}
	}
	if catalogCalls.Load() != 1 || decisionCalls.Load() != 0 || upstreamCalls.Load() != 2 {
		t.Fatalf("catalog=%d decisions=%d upstream=%d", catalogCalls.Load(), decisionCalls.Load(), upstreamCalls.Load())
	}
	// No verified, unexpired catalog means no login, even though login skips /decide.
	p.mu.Lock()
	p.active.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	p.mu.Unlock()
	out := httptest.NewRecorder()
	p.Handler().ServeHTTP(out, httptest.NewRequest("POST", loginPath, strings.NewReader(good)))
	if out.Code != 503 || upstreamCalls.Load() != 2 {
		t.Fatal("expired catalog allowed login")
	}
}
