package capability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRetiredIdentityRoutesNeverReachDependencies(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Errorf("retired route reached a dependency: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()
	proxy := newFixtureProxy(t, upstream.URL, cat)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/auth"},
		{http.MethodGet, "/auth/v1"},
		{http.MethodGet, "/auth/v1/oidc/authorize"},
		{http.MethodPost, "/auth/v1/clients"},
		{http.MethodPost, "/api/v1/admin/orgs/my-org/apps/app/provisioning/verify"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
			req.Header.Set("X-Organization-ID", "my-org")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			proxy.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status=%d want404 body=%s", w.Code, w.Body.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("dependency calls=%d want0", calls.Load())
	}
}
