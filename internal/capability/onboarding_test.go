package capability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The real proxy talks HTTP to a PDP stub. Grant authorization is covered by
// Grant's own service/API tests; this test proves the transport boundary.
func TestOrglessOnboardingHTTPDecisionHeaders(t *testing.T) {
	cat := loadFixtureCatalog(t)
	cases := []struct{ method, path, body, action string }{
		{"POST", "/api/v1/me/ensure", "", "user.materialize"},
		{"GET", "/api/v1/me", "", "user.read"},
		{"GET", "/api/v1/orgs", "", "organization.list"},
		{"POST", "/api/v1/orgs", `{"id":"new-org","name":"New"}`, "organization.create"},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			var pdp, upstream atomic.Int64
			allowed := true
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, exists := r.Header["X-Organization-Id"]; exists {
					t.Error("empty organization header was transmitted")
				}
				if r.URL.Path == "/api/v2/http-capabilities/decide" {
					pdp.Add(1)
					echoDecisionHandler(t, &allowed, "grant", "grant-management."+tc.action)(w, r)
					return
				}
				upstream.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()
			p := newFixtureProxy(t, server.URL, cat)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, req)
			if w.Code != 200 || pdp.Load() != 1 || upstream.Load() != 1 {
				t.Fatal(w.Code, w.Body.String(), pdp.Load(), upstream.Load())
			}
		})
	}
}

func TestLegacyMaterializeRouteNeverReachesDependencies(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	p := newFixtureProxy(t, server.URL, cat)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/materialize", nil)
	req.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound || calls.Load() != 0 {
		t.Fatalf("status=%d dependency calls=%d", w.Code, calls.Load())
	}
}

func TestOrglessDoesNotBypassCredentialOrTenantRequirements(t *testing.T) {
	cat := loadFixtureCatalog(t)
	for _, tc := range []struct {
		path, token string
		orgs        []string
	}{
		{"/api/v1/me", "", nil},
		{"/api/v1/orgs/org/groups", "Bearer token", nil},
		{"/api/v1/me", "Bearer token", []string{""}},
		{"/api/v1/me", "Bearer token", []string{"org", "org"}},
	} {
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
		p := newFixtureProxy(t, server.URL, cat)
		req := httptest.NewRequest("GET", tc.path, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
		}
		for _, org := range tc.orgs {
			req.Header.Add("X-Organization-ID", org)
		}
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, req)
		server.Close()
		// Header-shape validation can reject before bearer parsing. Both routes
		// must fail locally, without a PDP or upstream request.
		if (w.Code != 401 && w.Code != 422) || calls.Load() != 0 {
			t.Fatal(tc.path, w.Code, w.Body.String(), calls.Load())
		}
	}
}
