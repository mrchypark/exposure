package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/grantclient"
	"github.com/mrchypark/exposure/internal/readartifact"
	"github.com/mrchypark/exposure/internal/readiness"
	"github.com/mrchypark/exposure/internal/service"
)

func grantStatusAPI(t *testing.T, grantURL string, timeout time.Duration) (*API, *int) {
	t.Helper()
	schema := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digest, err := contracts.Digest(map[string]any{"artifactType": "exposure.read.v1", "exposureId": "exp", "exposureVersion": float64(1), "source": map[string]any{"namespace": "n", "objectType": "o", "schemaDigest": schema}, "projectionPointers": []string{"/x"}})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := readartifact.Parse([]byte(fmt.Sprintf(`{"artifactType":"exposure.read.v1","exposureId":"exp","exposureVersion":1,"artifactDigest":"%s","source":{"namespace":"n","objectType":"o","schemaDigest":"%s"},"projectionPointers":["/x"]}`, digest, schema)))
	if err != nil {
		t.Fatal(err)
	}
	sourceCalls := 0
	grant := grantclient.New(grantURL, http.DefaultClient, timeout, 4096)
	svc, err := service.New([]readartifact.Artifact{artifact}, grant, ps{&sourceCalls}, "server-app-key")
	if err != nil {
		t.Fatal(err)
	}
	return New(svc, readiness.New(), 1024, 1), &sourceCalls
}

func TestPublicGrantStatusContractIsUsefulAndBodySafe(t *testing.T) {
	const private = "private-grant-or-auth-refresh-detail"
	for _, tc := range []struct {
		name, body, code string
		status, want     int
	}{
		{"invalid bearer", `{"error":"` + private + `"}`, "unauthorized", http.StatusUnauthorized, http.StatusUnauthorized},
		{"expired bearer", `{"error":"expired ` + private + `"}`, "unauthorized", http.StatusUnauthorized, http.StatusUnauthorized},
		{"wrong organization", `{"error":"` + private + `"}`, "forbidden", http.StatusForbidden, http.StatusForbidden},
		{"wrong application", `{"error":"` + private + `"}`, "forbidden", http.StatusForbidden, http.StatusForbidden},
		{"Patch Data auth-refresh outage", `{"error":"` + private + `"}`, "dependency_unavailable", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
		{"Patch Data auth-refresh malformed", private, "dependency_unavailable", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
		{"Grant bad request", `{"error":"` + private + `"}`, "contract_invalid", http.StatusBadRequest, http.StatusUnprocessableEntity},
		{"Grant unprocessable request", `{"error":"` + private + `"}`, "contract_invalid", http.StatusUnprocessableEntity, http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grantCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				grantCalls++
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			api, sourceCalls := grantStatusAPI(t, server.URL, time.Second)
			response := httptest.NewRecorder()
			api.Handler().ServeHTTP(response, validReadRequest())
			wantBody := fmt.Sprintf("{\"schemaVersion\":1,\"errorCode\":%q}\n", tc.code)
			wantChallenge := ""
			if tc.want == http.StatusUnauthorized {
				wantChallenge = "Bearer"
			}
			challenge := response.Header().Values("WWW-Authenticate")
			challengeOK := len(challenge) == 0
			if wantChallenge != "" {
				challengeOK = len(challenge) == 1 && challenge[0] == wantChallenge
			}
			if response.Code != tc.want || response.Body.String() != wantBody || !challengeOK || grantCalls != 1 || *sourceCalls != 0 || strings.Contains(response.Body.String(), private) || strings.Contains(response.Body.String(), "safe") || strings.Contains(response.Body.String(), "data") {
				t.Fatalf("status=%d body=%q grant=%d source=%d", response.Code, response.Body.String(), grantCalls, *sourceCalls)
			}
		})
	}
}

func TestPublicMissingAuthorizationReturns401WithoutGrantOrBusinessBytes(t *testing.T) {
	grantCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { grantCalls++ }))
	defer server.Close()
	api, sourceCalls := grantStatusAPI(t, server.URL, time.Second)
	request := validReadRequest()
	request.Header.Del("Authorization")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	challenge := response.Header().Values("WWW-Authenticate")
	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"schemaVersion\":1,\"errorCode\":\"unauthorized\"}\n" || len(challenge) != 1 || challenge[0] != "Bearer" || grantCalls != 0 || *sourceCalls != 0 || strings.Contains(response.Body.String(), "data") {
		t.Fatalf("status=%d body=%q grant=%d source=%d", response.Code, response.Body.String(), grantCalls, *sourceCalls)
	}
}

func TestPublicGrantTimeoutReturns503WithoutSourceOrLeak(t *testing.T) {
	const private = "private-timeout-detail"
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}))
	defer server.Close()
	api, sourceCalls := grantStatusAPI(t, server.URL, 20*time.Millisecond)
	response := httptest.NewRecorder()
	start := time.Now()
	api.Handler().ServeHTTP(response, validReadRequest())
	called := false
	select {
	case <-entered:
		called = true
	default:
	}
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("WWW-Authenticate") != "" || time.Since(start) > time.Second || !called || *sourceCalls != 0 || strings.Contains(response.Body.String(), private) || strings.Contains(response.Body.String(), "data") {
		t.Fatalf("status=%d elapsed=%v body=%q source=%d", response.Code, time.Since(start), response.Body.String(), *sourceCalls)
	}
}

func TestPublicPolicyDenyRemainsStrict200DecisionThen403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request contracts.ReadGrantRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contracts.ReadGrantResponse{
			Allowed: false, Reason: "no_matching_binding", ExposureID: request.ExposureID,
			ExposureVersion: request.ExposureVersion, ArtifactDigest: request.ArtifactDigest,
			ResourceID: request.ResourceID, RequestBinding: request.RequestBinding,
			PrincipalDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			IssuedAt:        time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Minute),
		})
	}))
	defer server.Close()
	api, sourceCalls := grantStatusAPI(t, server.URL, time.Second)
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, validReadRequest())
	if response.Code != http.StatusForbidden || response.Header().Get("WWW-Authenticate") != "" || !strings.Contains(response.Body.String(), `"errorCode":"forbidden"`) || *sourceCalls != 0 || strings.Contains(response.Body.String(), "no_matching_binding") {
		t.Fatalf("status=%d body=%q source=%d", response.Code, response.Body.String(), *sourceCalls)
	}
}

func TestPublicMalformedGrant200Is503NotContract422(t *testing.T) {
	const private = "private-malformed-decision"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true,"error":"` + private + `"}`))
	}))
	defer server.Close()
	api, sourceCalls := grantStatusAPI(t, server.URL, time.Second)
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, validReadRequest())
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("WWW-Authenticate") != "" || !strings.Contains(response.Body.String(), `"errorCode":"dependency_unavailable"`) || *sourceCalls != 0 || strings.Contains(response.Body.String(), private) || strings.Contains(response.Body.String(), "data") {
		t.Fatalf("status=%d body=%q source=%d", response.Code, response.Body.String(), *sourceCalls)
	}
}
