package capability

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/exposure/internal/config"
)

func TestAuthorizedUpstreamResponsesCannotBeCached(t *testing.T) {
	for _, status := range []int{200, 206, 304} {
		for _, mode := range []string{"authorized", "public_authn"} {
			t.Run(fmt.Sprintf("%s/%d", mode, status), func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Cache-Control", "public, max-age=2592000")
					w.WriteHeader(status)
					if status != 304 {
						_, _ = w.Write([]byte("native bytes"))
					}
				}))
				defer upstream.Close()
				p, err := New(config.ProxyConfig{Origin: upstream.URL, MaxResponseBytes: 1024}, upstream.URL, upstream.Client(), 1)
				if err != nil {
					t.Fatal(err)
				}
				c := capability{AccessMode: mode, Method: "GET", Response: responsePolicy{MaxBytes: 1024, ErrorStatuses: []int{304}, ForwardHeaders: []string{"cache-control"}}}
				out := httptest.NewRecorder()
				p.forward(out, httptest.NewRequest("GET", "/file", nil), c, "", http.Header{}, nil)
				wantCache := "public, max-age=2592000"
				if mode == "authorized" {
					wantCache = "no-store"
				}
				if out.Code != status || out.Header().Get("Cache-Control") != wantCache {
					t.Fatalf("status%d cache%q", out.Code, out.Header().Get("Cache-Control"))
				}
				wantBody := "native bytes"
				if status == 304 {
					wantBody = ""
				}
				if out.Body.String() != wantBody {
					t.Fatal("native response body changed")
				}
			})
		}
	}
}
