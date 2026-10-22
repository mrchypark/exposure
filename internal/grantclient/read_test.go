package grantclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/dependency"
	"github.com/mrchypark/exposure/internal/operation"
)

var grantRequest = contracts.ReadGrantRequest{ExposureID: "e", ExposureVersion: 1, ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ResourceID: "r", RequestBinding: "b"}

const plantReadContractSHA256 = "1da9293bbac25c94acfd154083ea057d0dd3aa321703aa0b6d15545bcad2bb2b"

type plantReadContractVector struct {
	Path     string                     `json:"path"`
	Request  contracts.ReadGrantRequest `json:"request"`
	Expected struct {
		OperationID  string `json:"operationId"`
		ProviderID   string `json:"providerId"`
		ActionID     string `json:"actionId"`
		ResourceType string `json:"resourceType"`
	} `json:"expectedResponseSemantics"`
}

func loadPlantReadContract(t *testing.T) plantReadContractVector {
	t.Helper()
	body, err := os.ReadFile("testdata/plant_read_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if got := hex.EncodeToString(digest[:]); got != plantReadContractSHA256 {
		t.Fatalf("shared contract vector digest=%s", got)
	}
	var vector plantReadContractVector
	if err := contracts.StrictDecode(body, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestReadUsesFixedWireAndHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/exposure-authz/read" || r.Header.Get("Authorization") != "Bearer user" || r.Header.Get("X-Organization-ID") != "org" || r.Header.Get("X-Grant-App-Auth-Key") != "app" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		b, _ := io.ReadAll(r.Body)
		want := `{"exposureId":"e","exposureVersion":1,"artifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","requestBinding":"b"}`
		if string(b) != want {
			t.Fatalf("body=%s", b)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true,"reason":"ok","exposureId":"e","exposureVersion":1,"artifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resourceId":"r","requestBinding":"b","principalDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","issuedAt":"2025-01-01T00:00:00Z","expiresAt":"2030-01-01T00:00:00Z"}`))
	}))
	defer server.Close()
	c := New(server.URL, server.Client(), time.Second, 4096)
	_, err := c.Read(context.Background(), grantRequest, "Bearer user", "org", "app")
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadPlantUsesSeparateClosedOperationWire(t *testing.T) {
	vector := loadPlantReadContract(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/exposure-authz/decide" || r.URL.RawQuery != "" {
			t.Fatalf("request=%s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		b, _ := io.ReadAll(r.Body)
		descriptor, _ := operation.Lookup(vector.Request.OperationID)
		want, _ := json.Marshal(contracts.OperationDecisionRequestV2{
			OperationID: descriptor.ID, OperationVersion: descriptor.Version,
			ContractDigest: descriptor.ContractDigest,
			Resource:       contracts.OperationResourceV2{ID: vector.Request.ResourceID}, RequestBinding: vector.Request.RequestBinding,
		})
		if string(b) != string(want) || strings.Contains(string(b), "providerId") || strings.Contains(string(b), "actionId") || strings.Contains(string(b), "resourceType") {
			t.Fatalf("body=%s", b)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contracts.OperationDecisionResponseV2{
			Allowed: true, Reason: "ok", OperationID: vector.Expected.OperationID,
			OperationVersion: descriptor.Version, ContractDigest: descriptor.ContractDigest,
			ProviderID: vector.Expected.ProviderID, ActionID: vector.Expected.ActionID,
			Resource:        contracts.OperationResourceV2{Type: vector.Expected.ResourceType, ID: vector.Request.ResourceID},
			RequestBinding:  vector.Request.RequestBinding,
			PrincipalDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			IssuedAt:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		})
	}))
	defer server.Close()
	if _, err := New(server.URL, server.Client(), time.Second, 4096).Read(context.Background(), vector.Request, "Bearer user", "org", "app"); err != nil {
		t.Fatal(err)
	}
}

func TestReadPlantRejectsEveryTamperedV2ReplayEcho(t *testing.T) {
	descriptor, _ := operation.Lookup(operation.PlantGetID)
	request := grantRequest
	request.OperationID = descriptor.ID
	mutations := []struct {
		name   string
		change func(*contracts.OperationDecisionResponseV2)
	}{
		{"operation", func(v *contracts.OperationDecisionResponseV2) { v.OperationID = "plant.list" }},
		{"version", func(v *contracts.OperationDecisionResponseV2) { v.OperationVersion++ }},
		{"digest", func(v *contracts.OperationDecisionResponseV2) { v.ContractDigest = "sha256:" + strings.Repeat("0", 64) }},
		{"provider", func(v *contracts.OperationDecisionResponseV2) { v.ProviderID = "other" }},
		{"action", func(v *contracts.OperationDecisionResponseV2) { v.ActionID = "other.read" }},
		{"resource type", func(v *contracts.OperationDecisionResponseV2) { v.Resource.Type = "organization" }},
		{"resource id", func(v *contracts.OperationDecisionResponseV2) { v.Resource.ID = "other" }},
		{"binding", func(v *contracts.OperationDecisionResponseV2) { v.RequestBinding = "other" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				response := contracts.OperationDecisionResponseV2{Allowed: true, Reason: "ok", OperationID: descriptor.ID, OperationVersion: descriptor.Version, ContractDigest: descriptor.ContractDigest, ProviderID: descriptor.ProviderID, ActionID: descriptor.ActionID, Resource: contracts.OperationResourceV2{Type: descriptor.ResourceType, ID: request.ResourceID}, RequestBinding: request.RequestBinding, PrincipalDigest: strings.Repeat("b", 64), IssuedAt: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Minute)}
				mutation.change(&response)
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			if _, err := New(server.URL, server.Client(), time.Second, 4096).Read(context.Background(), request, "Bearer user", "org", "app"); err == nil {
				t.Fatal("tampered decision accepted")
			}
		})
	}
}

func TestReadMapsGrantStatusWithoutParsingOrLeakingLegacyBody(t *testing.T) {
	const secret = "private-grant-error-detail"
	for _, tc := range []struct {
		status int
		code   string
	}{
		{http.StatusUnauthorized, "unauthenticated"},
		{http.StatusForbidden, "access_denied"},
		{http.StatusServiceUnavailable, "upstream_failure"},
		{http.StatusBadGateway, "upstream_failure"},
		{http.StatusBadRequest, "invalid_request"},
		{http.StatusUnprocessableEntity, "invalid_request"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"error":"`+secret+`"}`+strings.Repeat("x", 8192))
			}))
			defer server.Close()
			_, err := New(server.URL, server.Client(), time.Second, 64).Read(context.Background(), grantRequest, "Bearer user", "org", "app")
			code, ok := dependency.ErrorCode(err)
			if !ok || code != tc.code || strings.Contains(err.Error(), secret) {
				t.Fatalf("status=%d code=%q ok=%v err=%v", tc.status, code, ok, err)
			}
		})
	}
}

func TestReadReturnsGrantStatusBeforeSlowLegacyBody(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		w.WriteHeader(http.StatusUnauthorized)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer cannot flush")
			return
		}
		_, _ = io.WriteString(w, `{"error":"private-partial`)
		flusher.Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	start := time.Now()
	_, err := New(server.URL, server.Client(), 2*time.Second, 64).Read(context.Background(), grantRequest, "Bearer user", "org", "app")
	if code, ok := dependency.ErrorCode(err); !ok || code != "unauthenticated" || time.Since(start) > 500*time.Millisecond || strings.Contains(err.Error(), "private-partial") {
		t.Fatalf("error=%v elapsed=%v", err, time.Since(start))
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Grant handler did not observe closed response body")
	}
}

func TestReadKeepsStrictDecisionSchemaOnSuccess(t *testing.T) {
	for _, body := range []string{
		`{"allowed":true}`,
		`{"allowed":true,"legacy":"ignored"}`,
		`{"error":"legacy-success-body"}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}))
		_, err := New(server.URL, server.Client(), time.Second, 4096).Read(context.Background(), grantRequest, "Bearer user", "org", "app")
		server.Close()
		if err == nil || strings.Contains(err.Error(), "legacy-success-body") {
			t.Fatalf("body=%s err=%v", body, err)
		}
	}
}
