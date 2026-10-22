package capability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

func TestCanonicalQueryRejectsUnregisteredAndDuplicateValues(t *testing.T) {
	policy := queryPolicy{Mode: "exact", Parameters: []queryParam{{Name: "plant", Format: "pocketbaseId", Required: true}}}
	if _, err := canonicalQuery("plant=123456789012345&other=x", policy); err == nil {
		t.Fatal("unknown query accepted")
	}
	if _, err := canonicalQuery("plant=123456789012345&plant=123456789012345", policy); err == nil {
		t.Fatal("duplicate query accepted")
	}
	got, err := canonicalQuery("plant=123456789012345", policy)
	if err != nil || got != "plant=123456789012345" {
		t.Fatalf("canonical query=%q err=%v", got, err)
	}
}

func TestAuthorizedProxyUsesOneUpstreamCallAndAcceptsJWTExtraClaims(t *testing.T) {
	var upstreamCalls, decisionCalls int
	var allowed = true
	decisionMode := "allow"
	var upstreamRawQuery, decisionCanonicalQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/http-capabilities/decide":
			decisionCalls++
			var in map[string]any
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Fatal(err)
			}
			credential := in["providerCredential"].(map[string]any)
			decisionCanonicalQuery, _ = in["canonicalQuery"].(string)
			now := time.Now().UTC()
			out := map[string]any{"allowed": allowed, "reason": "trusted_application", "providerId": in["providerId"], "pepClientId": in["pepClientId"], "catalogGeneration": in["catalogGeneration"], "catalogDigest": in["catalogDigest"], "capabilityId": in["capabilityId"], "capabilityVersion": in["capabilityVersion"], "contractDigest": in["contractDigest"], "actionId": "provider.item.read", "resourceType": "item", "resourceId": "abc", "method": "GET", "canonicalPath": "/items/abc", "canonicalQueryDigest": in["canonicalQueryDigest"], "forwardedHeaderDigest": in["forwardedHeaderDigest"], "bodyDigest": in["bodyDigest"], "bodyLength": in["bodyLength"], "providerCredentialDigest": in["providerCredentialDigest"], "providerSubject": credential["subject"], "providerAudience": credential["audience"], "requestBinding": in["requestBinding"], "principalDigest": strings.Repeat("a", 64), "issuedAt": now.Format(time.RFC3339Nano), "expiresAt": now.Add(5 * time.Second).Format(time.RFC3339Nano)}
			if decisionMode == "tamper" {
				out["canonicalPath"] = "/items/other"
			}
			if decisionMode == "stale" {
				out["expiresAt"] = now.Add(-time.Second).Format(time.RFC3339Nano)
			}
			if decisionMode == "ttl" {
				out["expiresAt"] = now.Add(6 * time.Second).Format(time.RFC3339Nano)
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			upstreamCalls++
			upstreamRawQuery = r.URL.RawQuery
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
				t.Fatalf("authorization=%q", got)
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer server.Close()
	action := "provider.item.read"
	cap := capability{CapabilityID: "item.read", Version: 1, Enabled: true, AccessMode: "authorized", Method: "GET", PathTemplate: "/items/{id}", ActionID: &action, Resource: &resource{Type: "item", ID: extractor{Kind: "pathSegment", Name: "id", Format: "asciiToken"}}, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "none", MaxBytes: 0}, Response: responsePolicy{MaxBytes: 1024, Redirects: "deny"}, ContractDigest: "sha256:" + strings.Repeat("b", 64)}
	p, err := New(config.ProxyConfig{ProviderID: "provider", PepClientID: "pep", Origin: server.URL, MaxRequestBytes: 1024, MaxResponseBytes: 1024, PublicAuthnGlobalCapacity: 1, PublicAuthnPeerCapacity: 1, PublicAuthnGlobalRefill: time.Hour, PublicAuthnPeerRefill: time.Hour, AuthnLimiterKey: "k"}, server.URL, server.Client(), 4)
	if err != nil {
		t.Fatal(err)
	}
	p.active = &catalog{SchemaVersion: 1, ProviderID: "provider", PepClientID: "pep", Generation: 1, CatalogDigest: "sha256:" + strings.Repeat("c", 64), Capabilities: []capability{cap}, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodGet, "/items/abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "org")
	response := httptest.NewRecorder()
	p.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK || upstreamCalls != 1 || decisionCalls != 1 {
		t.Fatalf("status=%d upstream=%d decision=%d", response.Code, upstreamCalls, decisionCalls)
	}
	allowed = false
	response = httptest.NewRecorder()
	p.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusForbidden || upstreamCalls != 1 {
		t.Fatalf("deny status=%d upstream=%d", response.Code, upstreamCalls)
	}
	allowed = true
	for _, mode := range []string{"tamper", "stale", "ttl"} {
		decisionMode = mode
		response = httptest.NewRecorder()
		p.Handler().ServeHTTP(response, req)
		if response.Code != http.StatusBadGateway || upstreamCalls != 1 {
			t.Fatalf("%s status=%d upstream=%d", mode, response.Code, upstreamCalls)
		}
	}
	decisionMode = "allow"
	p.active.Capabilities[0].Query = queryPolicy{Mode: "exact", Parameters: []queryParam{{Name: "a", Format: "asciiToken", Required: true}, {Name: "z", Format: "asciiToken", Required: true}}}
	rawQuery := "z=%62&a=%61"
	req.URL.RawQuery = rawQuery
	req.RequestURI = "/items/abc?" + rawQuery
	response = httptest.NewRecorder()
	p.Handler().ServeHTTP(response, req)
	if response.Code != 200 || upstreamRawQuery != rawQuery || decisionCanonicalQuery != "a=a&z=b" {
		t.Fatalf("query changed: status=%d raw=%q canonical=%q", response.Code, upstreamRawQuery, decisionCanonicalQuery)
	}
	beforeUpstream, beforeDecisions := upstreamCalls, decisionCalls
	for _, bad := range []string{"a=a&a=b&z=b", "a=a&z=b&unknown=x"} {
		req.URL.RawQuery = bad
		req.RequestURI = "/items/abc?" + bad
		response = httptest.NewRecorder()
		p.Handler().ServeHTTP(response, req)
		if response.Code != 422 || upstreamCalls != beforeUpstream || decisionCalls != beforeDecisions {
			t.Fatal("invalid query reached authorization or upstream")
		}
	}
}

func TestPublicAuthnLimiterAndConnectionNominatedHeadersFailClosed(t *testing.T) {
	l := &authnLimiter{key: []byte("k"), peers: map[string]tokenBucket{}, globalCapacity: 1, peerCapacity: 1, globalRefill: time.Hour, peerRefill: time.Hour}
	if _, ok := l.allow("127.0.0.1:1", "login", time.Now()); !ok {
		t.Fatal("first token rejected")
	}
	if _, ok := l.allow("127.0.0.1:1", "login", time.Now()); ok {
		t.Fatal("rate limit bypass")
	}
	h := http.Header{"Connection": {"X-Allowed"}, "X-Allowed": {"value"}}
	if _, err := forwardHeaders(h, []string{"X-Allowed"}); err == nil {
		t.Fatal("connection-nominated header accepted")
	}
}

func TestCatalogAndCapabilityDigestsAreRequiredBeforeSwap(t *testing.T) {
	action := "provider.item.read"
	cap := capability{CapabilityID: "item.read", Version: 1, Enabled: true, AccessMode: "authorized", Method: "GET", PathTemplate: "/items/{id}", ActionID: &action, Resource: &resource{Type: "item", ID: extractor{Kind: "pathSegment", Name: "id", Format: "asciiToken"}}, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "none", MaxBytes: 0}, Response: responsePolicy{MaxBytes: 32, Redirects: "deny"}}
	cap.ContractDigest = capabilityDigest(cap)
	c := &catalog{SchemaVersion: 1, ProviderID: "provider", PepClientID: "pep", Generation: 1, Capabilities: []capability{cap}, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	c.CatalogDigest = catalogDigest(c)
	p := &Proxy{cfg: config.ProxyConfig{ProviderID: "provider", PepClientID: "pep", ExpectedCatalogDigest: c.CatalogDigest, MaxResponseBytes: 32}}
	if err := p.validateCatalog(c); err != nil {
		t.Fatalf("valid digest rejected: %v", err)
	}
	c.Capabilities[0].Method = http.MethodPost
	if err := p.validateCatalog(c); err == nil {
		t.Fatal("tampered capability accepted")
	}
}

func TestRefreshInteroperatesWithGrantCanonicalContractDigestVector(t *testing.T) {
	// These literals are generated independently from Grant 89e8ce01's
	// serde_json::Value contract. Do not derive either digest through Exposure.
	const contractDigest = "sha256:e24b65bb4c4e37a170ed8fabcf94bab2111861b1b6d220395d5274f22f0bdf42"
	const catalogDigest = "sha256:833587bd54c6af1c79f7c56955fc5289d1b01a4e69d8462463afed85cc9caa0b"
	var body = grantCatalogVector(contractDigest, catalogDigest, false)
	grant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v2/http-capabilities/catalog/provider" || r.Header.Get("X-Grant-App-Auth-Key") != "app-key" {
			t.Fatalf("catalog request method=%s path=%s key=%q", r.Method, r.URL.Path, r.Header.Get("X-Grant-App-Auth-Key"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer grant.Close()

	p, err := New(config.ProxyConfig{ProviderID: "provider", PepClientID: "pep", Origin: grant.URL, ExpectedCatalogDigest: catalogDigest, AppAuthKey: "app-key", MaxResponseBytes: 32}, grant.URL, grant.Client(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("Grant vector rejected: %v", err)
	}
	body = grantCatalogVector(contractDigest, catalogDigest, true)
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("tampered Grant vector accepted")
	}
}

func grantCatalogVector(contractDigest, catalogDigest string, tamper bool) string {
	method := "GET"
	if tamper {
		method = "POST"
	}
	return fmt.Sprintf(`{"schemaVersion":1,"providerId":"provider","pepClientId":"pep","generation":1,"catalogDigest":%q,"capabilities":[{"capabilityId":"item.read","version":1,"enabled":true,"accessMode":"authorized","method":%q,"pathTemplate":"/items/{id}","actionId":"provider.item.read","resource":{"type":"item","id":{"kind":"pathSegment","name":"id","format":"asciiToken"}},"query":{"mode":"none"},"request":{"body":"none","maxBytes":0,"forwardHeaders":[]},"response":{"maxBytes":32,"forwardHeaders":[],"redirects":"deny"},"contractDigest":%q}],"issuedAt":"2026-08-28T00:00:00Z","expiresAt":%q}`, catalogDigest, method, contractDigest, time.Now().UTC().Add(time.Minute).Format(time.RFC3339))
}

func TestReadBodyRejectsDuplicateJSONKeysBeforeExtractionOrForwarding(t *testing.T) {
	policy := requestPolicy{Body: "json", MaxBytes: 1024}
	for _, body := range []string{
		`{"id":"first","id":"last"}`,
		`{"outer":{"id":"first","id":"last"}}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/items", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if _, err := readBody(r, policy, 1024); err == nil {
			t.Fatalf("duplicate JSON key accepted: %s", body)
		}
	}
}

func TestInvalidUTF8JSONNeverReachesUpstream(t *testing.T) {
	var upstreamCalls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ }))
	defer server.Close()
	p, err := New(config.ProxyConfig{Origin: server.URL, MaxRequestBytes: 1024, MaxResponseBytes: 1024, AuthnLimiterKey: "k", PublicAuthnGlobalCapacity: 10, PublicAuthnPeerCapacity: 10, PublicAuthnGlobalRefill: time.Hour, PublicAuthnPeerRefill: time.Hour}, server.URL, server.Client(), 1)
	if err != nil {
		t.Fatal(err)
	}
	p.active = &catalog{ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339), Capabilities: []capability{{Enabled: true, AccessMode: "public_authn", Method: http.MethodPost, PathTemplate: "/items", Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "json", MaxBytes: 1024}, Response: responsePolicy{MaxBytes: 1024, Redirects: "deny"}}}}
	req := httptest.NewRequest(http.MethodPost, "/items", bytes.NewReader([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.1:1234"
	result := httptest.NewRecorder()
	p.Handler().ServeHTTP(result, req)
	if result.Code != http.StatusUnprocessableEntity || upstreamCalls != 0 {
		t.Fatalf("status=%d upstream=%d", result.Code, upstreamCalls)
	}
}

func TestPublicAuthnPeerMapHardCapEvictsOldest(t *testing.T) {
	l := &authnLimiter{key: []byte("k"), peers: map[string]tokenBucket{}, globalCapacity: 5000, peerCapacity: 1, globalRefill: time.Hour, peerRefill: time.Hour}
	now := time.Now()
	for i := 0; i < maxAuthnPeers; i++ {
		remote := fmt.Sprintf("10.%d.%d.%d:1234", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		if _, ok := l.allow(remote, "login", now); !ok {
			t.Fatalf("peer %d rejected before hard cap", i)
		}
	}
	if got := len(l.peers); got != maxAuthnPeers {
		t.Fatalf("peer map length=%d", got)
	}
	if _, ok := l.allow("11.0.0.1:1234", "login", now); !ok {
		t.Fatal("new peer rejected after deterministic oldest eviction")
	}
	if got := len(l.peers); got != maxAuthnPeers {
		t.Fatalf("peer map exceeded cap: %d", got)
	}
}

func TestPublicAuthnPeerMapPrunesStaleEntriesBeforeAdmission(t *testing.T) {
	l := &authnLimiter{key: []byte("k"), peers: map[string]tokenBucket{}, globalCapacity: 10, peerCapacity: 1, globalRefill: time.Hour, peerRefill: time.Hour}
	now := time.Now()
	if _, ok := l.allow("192.0.2.1:1234", "login", now); !ok {
		t.Fatal("initial peer rejected")
	}
	if _, ok := l.allow("192.0.2.2:1234", "login", now.Add(authnPeerTTL+time.Nanosecond)); !ok {
		t.Fatal("fresh peer rejected after stale prune")
	}
	if got := len(l.peers); got != 1 {
		t.Fatalf("stale entries retained: %d", got)
	}
}

func TestCapabilityDigestPreservesGrantUint64Precision(t *testing.T) {
	const grantDigest = "sha256:9cf5ce5b7a8b1a0f54caa7a5edef00e60017522165e25e5759b506c4f833c452"
	action := "provider.item.read"
	cap := capability{CapabilityID: "item.read", Version: 9007199254740993, Enabled: true, AccessMode: "authorized", Method: http.MethodGet, PathTemplate: "/items/{id}", ActionID: &action, Resource: &resource{Type: "item", ID: extractor{Kind: "pathSegment", Name: "id", Format: "asciiToken"}}, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "none", MaxBytes: 0, ForwardHeaders: []string{}}, Response: responsePolicy{MaxBytes: 32, ForwardHeaders: []string{}, Redirects: "deny"}}
	if got := capabilityDigest(cap); got != grantDigest {
		t.Fatalf("Grant uint64 digest=%s", got)
	}
}

func TestDataHandlerDoesNotExposeAdminHealth(t *testing.T) {
	p := &Proxy{sem: make(chan struct{}, 1)}
	r := httptest.NewRecorder()
	p.Handler().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "http://exposure/healthz", nil))
	if r.Code == http.StatusOK {
		t.Fatal("data handler exposed admin health")
	}
}

func TestResponseCapAndWriteTransportFailureDoNotLeakProviderBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("0123456789")) }))
	defer server.Close()
	p, err := New(config.ProxyConfig{Origin: server.URL, MaxResponseBytes: 4}, server.URL, server.Client(), 1)
	if err != nil {
		t.Fatal(err)
	}
	cap := capability{Method: http.MethodGet, AccessMode: "public_authn", Response: responsePolicy{MaxBytes: 10, Redirects: "deny"}}
	w := httptest.NewRecorder()
	p.forward(w, httptest.NewRequest(http.MethodGet, "/login", nil), cap, "", http.Header{}, nil)
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "0123") {
		t.Fatalf("cap result=%d body=%q", w.Code, w.Body.String())
	}
	p.http = &http.Client{Transport: roundTripError{}}
	cap.Method = http.MethodPost
	w = httptest.NewRecorder()
	p.forward(w, httptest.NewRequest(http.MethodPost, "/items", nil), cap, "", http.Header{}, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "unknown_outcome") {
		t.Fatalf("write result=%d body=%q", w.Code, w.Body.String())
	}
}

type roundTripError struct{}

func (roundTripError) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

func jwtWithExtraClaims(t *testing.T) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"sub": "user-1", "client_id": "client-1", "iss": "https://issuer", "aud": "audience", "exp": 123})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestMatchTemplateRejectsAmbiguityAtExecution(t *testing.T) {
	caps := []capability{{Enabled: true, Method: http.MethodGet, PathTemplate: "/api/items/{id}"}, {Enabled: true, Method: http.MethodGet, PathTemplate: "/api/items/{other}"}}
	if cap, _ := findCapability(caps, http.MethodGet, "/api/items/abc"); cap != nil {
		t.Fatal("ambiguous capability accepted")
	}
}

func TestIncomingPathRejectsEncodedOrTraversalForms(t *testing.T) {
	for _, raw := range []string{"/api/%2fitems", "/api//items", "/api/../items", "/api/items\\x"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := &http.Request{URL: u, RequestURI: raw}
		if err := validateIncomingPath(r); err == nil {
			t.Fatalf("unsafe path accepted: %s", raw)
		}
	}
}

func TestForwardHeadersStripIdentityAndRoutingHeaders(t *testing.T) {
	h := http.Header{"Accept": {"application/json"}, "Forwarded": {"for=bad"}, "X-Forwarded-For": {"bad"}, "X-Grant-App-Auth-Key": {"bad"}, "Authorization": {"Bearer token"}}
	out, err := forwardHeaders(h, []string{"Accept"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Get("Accept") != "application/json" || len(out) != 1 {
		t.Fatalf("headers=%v", out)
	}
}
