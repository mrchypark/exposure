package capability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/exposure/internal/config"
)

func TestServiceCredentialForwardingAndCatalogBoundary(t *testing.T) {
	const secret = "synthetic-private-data-token"
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != secret {
			t.Error("provider did not receive configured service credential")
		}
		for name := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-exposure-") {
				t.Fatal("provider received internal authorization evidence")
			}
		}
		_, _ = w.Write([]byte(`{"id":"record"}`))
	}))
	defer upstream.Close()
	p, err := New(config.ProxyConfig{AuthorizationMode: "service-token", UpstreamToken: secret, Origin: upstream.URL, MaxResponseBytes: 1024}, "http://127.0.0.1:8080", upstream.Client(), 1)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/items/record", nil)
	r.Header.Set("Authorization", "Bearer end-user-token")
	w := httptest.NewRecorder()
	p.forward(w, r, capability{AccessMode: "authorized", Request: requestPolicy{Authorization: "service-token"}, Response: responsePolicy{MaxBytes: 1024, Redirects: "deny"}}, "", http.Header{}, nil)
	if calls != 1 || w.Code != 200 || strings.Contains(w.Body.String(), secret) {
		t.Fatalf("provider forwarding status=%d calls=%d", w.Code, calls)
	}
	// Without a verified active catalog, the real handler never reaches upstream.
	before := calls
	w = httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	if w.Code < 400 || calls != before {
		t.Fatal("unready catalog reached privileged upstream")
	}
	if err := validateCapability(capability{AccessMode: "public_authn", Request: requestPolicy{Authorization: "service-token"}}); err == nil {
		t.Fatal("public authentication accepted service credential")
	}
}
