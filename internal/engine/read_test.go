package engine

import (
	"context"
	"github.com/mrchypark/exposure/internal/contracts"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadObjectUsesFixedWire(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/internal/v1/objects:read" {
			t.Fatal(r.Method, r.URL.Path)
		}
		for _, name := range []string{"Authorization", "X-Organization-ID", "X-Grant-App-Auth-Key", "X-Exposure-ID", "X-Artifact-Digest"} {
			if r.Header.Get(name) != "" {
				t.Fatalf("unexpected %s", name)
			}
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"namespace":"n","objectType":"o","schemaDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r"}` {
			t.Fatal(string(b))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"namespace":"n","objectType":"o","schemaDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","resourceVersion":2,"rawResource":{"x":"y"}}`))
	}))
	defer s.Close()
	c := New(s.URL, s.Client(), time.Second, 4096)
	out, err := c.ReadObject(context.Background(), contracts.SourceReadRequest{Namespace: "n", ObjectType: "o", SchemaDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ResourceID: "r"})
	if err != nil || out.ResourceVersion != 2 {
		t.Fatal(out, err)
	}
}
