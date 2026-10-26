package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/readartifact"
	"github.com/mrchypark/exposure/internal/readiness"
	"github.com/mrchypark/exposure/internal/service"
)

type pg struct{ n *int }

func (g pg) Read(_ context.Context, q contracts.ReadGrantRequest, _, _, _ string) (contracts.ReadGrantResponse, error) {
	(*g.n)++
	response := contracts.ReadGrantResponse{Allowed: true, Reason: "ok", ExposureID: q.ExposureID, ExposureVersion: q.ExposureVersion, ArtifactDigest: q.ArtifactDigest, ResourceID: q.ResourceID, RequestBinding: q.RequestBinding, PrincipalDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)}
	return response, nil
}

type ps struct{ n *int }

func (s ps) ReadObject(_ context.Context, a readartifact.Artifact, resourceID string) (contracts.SourceObject, error) {
	(*s.n)++
	version := int64(0)
	return contracts.SourceObject{Kind: a.SourceKind(), ResourceID: resourceID, ResourceVersion: &version, RawResource: map[string]any{"x": "safe"}}, nil
}

func readAPI(t *testing.T) (*API, *int, *int) {
	t.Helper()
	schema := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	d, _ := contracts.Digest(map[string]any{"artifactType": "exposure.read.v1", "exposureId": "exp", "exposureVersion": float64(1), "source": map[string]any{"namespace": "n", "objectType": "o", "schemaDigest": schema}, "projectionPointers": []string{"/x"}})
	a, err := readartifact.Parse([]byte(fmt.Sprintf(`{"artifactType":"exposure.read.v1","exposureId":"exp","exposureVersion":1,"artifactDigest":"%s","source":{"namespace":"n","objectType":"o","schemaDigest":"%s"},"projectionPointers":["/x"]}`, d, schema)))
	if err != nil {
		t.Fatal(err)
	}
	g, s := 0, 0
	svc, err := service.New([]readartifact.Artifact{a}, pg{&g}, ps{&s}, "app")
	if err != nil {
		t.Fatal(err)
	}
	return New(svc, readiness.New(), 1024, 1), &g, &s
}

func TestOnlyReadRoutesReachable(t *testing.T) {
	a, g, s := readAPI(t)
	for _, path := range []string{"/metrics", "/api/v1/orgs/x", "/v1/operations", "/v1/resources:page"} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 404 || *g != 0 || *s != 0 {
			t.Fatal(path, w.Code, *g, *s)
		}
	}
	r := validReadRequest()
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	var response service.ReadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || *g != 1 || *s != 1 || response.ExposureID != "exp" || response.ResourceID != "r" || response.ResourceVersion == nil || *response.ResourceVersion != 0 || len(response.Data) != 1 || response.Data["x"] != "safe" || strings.Contains(w.Body.String(), "rawResource") {
		t.Fatal(w.Code, w.Body.String(), *g, *s)
	}
}

func TestNonCanonicalProtectedPathsDoNotRedirectOrCallDependencies(t *testing.T) {
	paths := []string{
		"/v1//exposures/exp/resources/r",
		"/v1/./exposures/exp/resources/r",
		"/v1/segment/../exposures/exp/resources/r",
		"/v1/exposures//exp/resources/r",
		"/v1/exposures/./exp/resources/r",
		"/v1/exposures/segment/../exp/resources/r",
		"/v1/exposures/exp/resources//r",
		"/v1/exposures/exp/resources/./r",
		"/v1/exposures/exp/resources/segment/../r",
	}
	for _, requestPath := range paths {
		t.Run(requestPath, func(t *testing.T) {
			a, grant, source := readAPI(t)
			request := httptest.NewRequest(http.MethodGet, requestPath, nil)
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("X-Organization-ID", "org")
			response := httptest.NewRecorder()
			a.Handler().ServeHTTP(response, request)
			if response.Code < 400 || response.Code >= 500 || response.Header().Get("Location") != "" || *grant != 0 || *source != 0 || response.Body.Len() > 256 {
				t.Fatalf("status=%d location=%q grant=%d source=%d body=%q", response.Code, response.Header().Get("Location"), *grant, *source, response.Body.String())
			}
		})
	}
}

func validReadRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/exposures/exp/resources/r", nil)
	r.Header.Set("Authorization", "Bearer token")
	r.Header.Set("X-Organization-ID", "org")
	return r
}

func TestReadAcceptsRFC6750BearerForms(t *testing.T) {
	for _, authorization := range []string{
		"bearer token",
		"BEARER token",
		"BeArEr    token",
		"Bearer AZaz09-._~+/",
		"Bearer token=",
		"Bearer token===",
	} {
		t.Run(authorization, func(t *testing.T) {
			a, grant, source := readAPI(t)
			request := validReadRequest()
			request.Header.Set("Authorization", authorization)
			response := httptest.NewRecorder()
			a.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusOK || *grant != 1 || *source != 1 || response.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("authorization=%q status=%d grant=%d source=%d challenge=%q", authorization, response.Code, *grant, *source, response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestReadRejectsInvalidRequestsBeforeDependencies(t *testing.T) {
	tests := []struct {
		name string
		set  func(*http.Request)
	}{
		{"HEAD", func(r *http.Request) { r.Method = http.MethodHead; r.Header.Set("X-Correlation-ID", "request_1") }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=1" }},
		{"force query", func(r *http.Request) { r.URL.ForceQuery = true }},
		{"fixed length body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")); r.ContentLength = 1 }},
		{"chunked body", func(r *http.Request) { r.TransferEncoding = []string{"chunked"}; r.ContentLength = -1 }},
		{"escaped path", func(r *http.Request) { r.URL.RawPath = "/v1/exposures/exp/resources/%72" }},
		{"duplicate authorization", func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") }},
		{"duplicate organization", func(r *http.Request) { r.Header.Add("X-Organization-ID", "other") }},
		{"connection authorization", func(r *http.Request) { r.Header.Set("Connection", "Authorization") }},
		{"connection organization", func(r *http.Request) { r.Header.Set("Connection", "X-Organization-ID") }},
		{"connection app key", func(r *http.Request) { r.Header.Set("Connection", "X-Grant-App-Auth-Key") }},
		{"caller app key", func(r *http.Request) { r.Header.Set("X-Grant-App-Auth-Key", "caller") }},
		{"non bearer", func(r *http.Request) { r.Header.Set("Authorization", "Basic token") }},
		{"empty bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }},
		{"whitespace bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer \t") }},
		{"tab separator bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer\ttoken") }},
		{"control bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer token\x01") }},
		{"comma bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer token,other") }},
		{"bad padding bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer token=other") }},
		{"padding only bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ===") }},
		{"missing authorization", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"missing organization", func(r *http.Request) { r.Header.Del("X-Organization-ID") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, grant, source := readAPI(t)
			r := validReadRequest()
			tc.set(r)
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			wantStatus := http.StatusUnprocessableEntity
			switch tc.name {
			case "non bearer", "empty bearer", "whitespace bearer", "tab separator bearer", "control bearer", "comma bearer", "bad padding bearer", "padding only bearer", "missing authorization":
				wantStatus = http.StatusUnauthorized
			}
			if w.Code != wantStatus || *grant != 0 || *source != 0 {
				t.Fatalf("status=%d grant=%d source=%d body=%q", w.Code, *grant, *source, w.Body.String())
			}
			if tc.name == "HEAD" && w.Body.String() != "{\"schemaVersion\":1,\"errorCode\":\"invalid_request\",\"correlationId\":\"request_1\"}\n" {
				t.Fatalf("body=%q", w.Body.String())
			}
			if wantStatus == http.StatusUnauthorized {
				if values := w.Header().Values("WWW-Authenticate"); len(values) != 1 || values[0] != "Bearer" {
					t.Fatalf("challenge=%q", values)
				}
			} else if w.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("unexpected challenge=%q", w.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestReadBoundsSuccessfulResponse(t *testing.T) {
	a, grant, source := readAPI(t)
	a.maxResponse = 1
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, validReadRequest())
	if w.Code != http.StatusServiceUnavailable || *grant != 1 || *source != 1 || w.Body.String() != "{\"schemaVersion\":1,\"errorCode\":\"response_unavailable\"}\n" || strings.Contains(w.Body.String(), "data") {
		t.Fatalf("status=%d grant=%d source=%d body=%q", w.Code, *grant, *source, w.Body.String())
	}
}

func TestForwardingHeadersDoNotChangeAPIBehavior(t *testing.T) {
	a, grant, source := readAPI(t)
	request := validReadRequest()
	request.Header.Set("Forwarded", "for=203.0.113.7;proto=https;host=public.example")
	request.Header.Set("X-Forwarded-For", "203.0.113.7")
	request.Header.Set("X-Forwarded-Host", "public.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	a.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Location") != "" || *grant != 1 || *source != 1 {
		t.Fatalf("status=%d location=%q grant=%d source=%d body=%q", response.Code, response.Header().Get("Location"), *grant, *source, response.Body.String())
	}
	for name, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'none'",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := response.Header().Get(name); got != want {
			t.Fatalf("%s=%q want=%q", name, got, want)
		}
	}
}
func TestReadinessHasNoLegacyGates(t *testing.T) {
	a, _, _ := readAPI(t)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatal("healthz", w.Code)
	}
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK || w.Body.String() != "{\"ready\":true,\"checks\":{}}" {
		t.Fatalf("readyz status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestHealthAndReadyRejectImplicitHEAD(t *testing.T) {
	a, _, _ := readAPI(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodHead, path, nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d", path, w.Code)
		}
	}
}
