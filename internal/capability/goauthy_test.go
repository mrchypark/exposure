package capability

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

func goauthyJWT(t *testing.T, payload string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

func TestGoauthyCredentialUsesConfiguredIssuerNamespaceAndPinnedApplicationAudience(t *testing.T) {
	cfg := config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://gw-auth.dev.conalog.com", GoauthyApplicationID: "ied-data"}
	token := goauthyJWT(t, `{"iss":"https://attacker.invalid","sub":"user-1","aud":["oauth-resource"],"azp":"grant-ied-management/data","exp":1}`)
	r := httptest.NewRequest("GET", "/items/one", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Organization-ID", "org1")
	auth, org, subject, audience, err := bearerIdentity(r, cfg)
	if err != nil || auth != "Bearer "+token || org != "org1" || subject != "goauthy:https://gw-auth.dev.conalog.com/user-1" || audience != "ied-data" {
		t.Fatalf("auth=%q org=%q subject=%q audience=%q err=%v", auth, org, subject, audience, err)
	}
}

func TestGoauthyCredentialNamespacesSameJWTSubjectByConfiguredIssuer(t *testing.T) {
	token := goauthyJWT(t, `{"iss":"https://untrusted.invalid","sub":"user-1"}`)
	issuers := []string{"https://issuer-a.example", "https://issuer-b.example"}
	subjects := make([]string, 0, len(issuers))
	for _, issuer := range issuers {
		r := httptest.NewRequest(http.MethodGet, "/items/one", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Organization-ID", "org1")
		_, _, subject, _, err := bearerIdentity(r, config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: issuer, GoauthyApplicationID: "ied-data"})
		if err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, subject)
	}
	if subjects[0] == subjects[1] || subjects[0] != "goauthy:https://issuer-a.example/user-1" || subjects[1] != "goauthy:https://issuer-b.example/user-1" {
		t.Fatalf("subjects=%q", subjects)
	}
}

func TestGoauthyDecisionRejectsRawSubjectEcho(t *testing.T) {
	var upstreamCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/http-capabilities/decide" {
			upstreamCalls++
			w.WriteHeader(http.StatusOK)
			return
		}
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatal(err)
		}
		credential := in["providerCredential"].(map[string]any)
		if credential["subject"] != "goauthy:https://issuer-a.example/user-1" || credential["audience"] != "ied-data" {
			t.Fatalf("credential=%v", credential)
		}
		now := time.Now().UTC()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allowed": true, "reason": "test", "providerId": in["providerId"], "pepClientId": in["pepClientId"],
			"catalogGeneration": in["catalogGeneration"], "catalogDigest": in["catalogDigest"], "capabilityId": in["capabilityId"], "capabilityVersion": in["capabilityVersion"], "contractDigest": in["contractDigest"],
			"actionId": "provider.item.read", "resourceType": "item", "resourceId": "one", "method": "GET", "canonicalPath": "/items/one",
			"canonicalQueryDigest": in["canonicalQueryDigest"], "forwardedHeaderDigest": in["forwardedHeaderDigest"], "bodyDigest": in["bodyDigest"], "bodyLength": in["bodyLength"], "providerCredentialDigest": in["providerCredentialDigest"],
			"providerSubject": "user-1", "providerAudience": credential["audience"], "requestBinding": in["requestBinding"], "principalDigest": strings.Repeat("a", 64),
			"issuedAt": now.Format(time.RFC3339Nano), "expiresAt": now.Add(time.Second).Format(time.RFC3339Nano),
		})
	}))
	defer server.Close()
	action := "provider.item.read"
	cap := capability{CapabilityID: "item.read", Version: 1, Enabled: true, AccessMode: "authorized", Method: http.MethodGet, PathTemplate: "/items/{id}", ActionID: &action, Resource: &resource{Type: "item", ID: extractor{Kind: "pathSegment", Name: "id", Format: "asciiToken"}}, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "none"}, Response: responsePolicy{MaxBytes: 1024, Redirects: "deny"}}
	cap.ContractDigest = capabilityDigest(cap)
	p, err := New(config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://issuer-a.example", GoauthyApplicationID: "ied-data", ProviderID: "provider", PepClientID: "pep", Origin: server.URL, MaxRequestBytes: 1024, MaxResponseBytes: 1024, AuthnLimiterKey: "k", PublicAuthnGlobalCapacity: 1, PublicAuthnPeerCapacity: 1, PublicAuthnGlobalRefill: time.Hour, PublicAuthnPeerRefill: time.Hour}, server.URL, server.Client(), 1)
	if err != nil {
		t.Fatal(err)
	}
	p.active = &catalog{SchemaVersion: 1, ProviderID: "provider", PepClientID: "pep", Generation: 1, CatalogDigest: "sha256:" + strings.Repeat("c", 64), Capabilities: []capability{cap}, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	req := httptest.NewRequest(http.MethodGet, "/items/one", nil)
	req.Header.Set("Authorization", "Bearer "+goauthyJWT(t, `{"iss":"https://untrusted.invalid","sub":"user-1"}`))
	req.Header.Set("X-Organization-ID", "org1")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway || upstreamCalls != 0 {
		t.Fatalf("status=%d upstream=%d", w.Code, upstreamCalls)
	}
}

func TestGoauthyCredentialRejectsMalformedOrOpaqueTokens(t *testing.T) {
	cfg := config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://gw-auth.dev.conalog.com", GoauthyApplicationID: "ied-data"}
	for _, token := range []string{
		"opaque-token",
		"header.payload.signature",
		goauthyJWT(t, `{`),
		goauthyJWT(t, `{"sub":"one","sub":"two"}`),
		goauthyJWT(t, `{"azp":"grant-ied-data"}`),
	} {
		r := httptest.NewRequest("GET", "/items/one", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Organization-ID", "org1")
		if _, _, _, _, err := bearerIdentity(r, cfg); err == nil {
			t.Fatalf("invalid Goauthy credential accepted: %q", token)
		}
	}
}
