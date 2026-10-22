package capability

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/exposure/internal/config"
)

func TestBoundedUpstreamStatusContract(t *testing.T) {
	for _, status := range []int{200, 201, 204, 400, 401, 403, 404, 409, 422, 500, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := `{"error":"fixture"}`
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Set-Cookie", "upstream-private=value")
				w.WriteHeader(status)
				if status != 204 {
					_, _ = w.Write([]byte(body))
				}
			}))
			defer upstream.Close()
			p, err := New(config.ProxyConfig{Origin: upstream.URL, MaxResponseBytes: 128}, "http://127.0.0.1:8080", upstream.Client(), 1)
			if err != nil {
				t.Fatal(err)
			}
			cap := capability{Method: "GET", Response: responsePolicy{MaxBytes: 128, Redirects: "deny", ForwardHeaders: []string{"Content-Type"}, ErrorStatuses: []int{400, 401, 403, 404, 409, 422}}}
			out := httptest.NewRecorder()
			p.forward(out, httptest.NewRequest("GET", "/items", nil), cap, "", http.Header{}, nil)
			expected := status
			if status == 500 || status == 302 {
				expected = 502
			}
			if out.Code != expected {
				t.Fatalf("got%d want%d", out.Code, expected)
			}
			if out.Header().Get("Set-Cookie") != "" {
				t.Fatal("upstream cookie leaked")
			}
			if expected == status && status != 204 && out.Body.String() != body {
				t.Fatal("upstream body changed")
			}
			if status == 204 && out.Body.Len() != 0 {
				t.Fatal("204 acquired body")
			}
			cap.Response.MaxBytes = 1
			out = httptest.NewRecorder()
			p.forward(out, httptest.NewRequest("GET", "/items", nil), cap, "", http.Header{}, nil)
			if status != 204 && out.Code != 502 {
				t.Fatal("oversize upstream response escaped bound")
			}
		})
	}
}
