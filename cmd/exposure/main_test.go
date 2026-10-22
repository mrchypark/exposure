package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/readartifact"
)

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

func TestInternalHTTPClientDisablesEnvironmentProxyAndTLS(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	c := internalHTTPClient(config.Config{DependencyTimeout: time.Second})
	transport, ok := c.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig != nil {
		t.Fatalf("transport=%#v", c.Transport)
	}
}

func TestInternalHTTPClientDoesNotFollowRedirects(t *testing.T) {
	targetCalled := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalled <- struct{}{}
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	response, err := internalHTTPClient(config.Config{DependencyTimeout: time.Second}).Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", response.StatusCode)
	}
	select {
	case <-targetCalled:
		t.Fatal("redirect target called")
	default:
	}
}

func TestUsesSource(t *testing.T) {
	schema := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digest, err := contracts.Digest(map[string]any{"artifactType": "exposure.read.v1", "exposureId": "exp", "exposureVersion": float64(1), "source": map[string]any{"namespace": "ns", "objectType": "o", "schemaDigest": schema}, "projectionPointers": []string{"/x"}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := readartifact.Parse([]byte(fmt.Sprintf(`{"artifactType":"exposure.read.v1","exposureId":"exp","exposureVersion":1,"artifactDigest":"%s","source":{"namespace":"ns","objectType":"o","schemaDigest":"%s"},"projectionPointers":["/x"]}`, digest, schema)))
	if err != nil {
		t.Fatal(err)
	}
	if !usesSource([]readartifact.Artifact{a}, readartifact.SourceComposObject) || usesSource([]readartifact.Artifact{a}, readartifact.SourcePatchDataPlant) {
		t.Fatal("source detection mismatch")
	}
}
