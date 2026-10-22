package capability

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

func echoDecisionHandler(t *testing.T, allowed *bool, resourceID string, actionID string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatal(err)
		}
		echoDecisionMap(t, allowed, in, resourceID, actionID)(w, r)
	}
}

func echoDecisionMap(t *testing.T, allowed *bool, in map[string]any, resourceID string, actionID string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now().UTC()
		credential := in["providerCredential"].(map[string]any)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allowed": *allowed, "reason": "trusted_application",
			"providerId": in["providerId"], "pepClientId": in["pepClientId"],
			"catalogGeneration": in["catalogGeneration"], "catalogDigest": in["catalogDigest"],
			"capabilityId": in["capabilityId"], "capabilityVersion": in["capabilityVersion"],
			"contractDigest": in["contractDigest"], "actionId": actionID,
			"resourceType": in["resourceType"], "resourceId": resourceID,
			"method": in["method"], "canonicalPath": in["canonicalPath"],
			"canonicalQueryDigest":  in["canonicalQueryDigest"],
			"forwardedHeaderDigest": in["forwardedHeaderDigest"],
			"bodyDigest":            in["bodyDigest"], "bodyLength": in["bodyLength"],
			"providerCredentialDigest": in["providerCredentialDigest"],
			"providerSubject":          credential["subject"], "providerAudience": credential["audience"],
			"requestBinding":  in["requestBinding"],
			"principalDigest": strings.Repeat("a", 64),
			"issuedAt":        now.Format(time.RFC3339Nano),
			"expiresAt":       now.Add(5 * time.Second).Format(time.RFC3339Nano),
		})
	}
}

func loadFixtureCatalog(t *testing.T) *catalog {
	t.Helper()
	b, err := os.ReadFile("testdata/grant-management-full.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion uint64       `json:"schemaVersion"`
		Generation    uint64       `json:"generation"`
		Capabilities  []capability `json:"capabilities"`
		CatalogDigest string       `json:"catalogDigest"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for i := range fixture.Capabilities {
		c := &fixture.Capabilities[i]
		if err := validateCapability(*c); err != nil {
			t.Fatalf("capability %s: %v", c.CapabilityID, err)
		}
		if c.ContractDigest != capabilityDigest(*c) {
			t.Fatalf("capability %s contract digest mismatch", c.CapabilityID)
		}
	}
	cat := &catalog{
		SchemaVersion: fixture.SchemaVersion,
		ProviderID:    "grant-management",
		PepClientID:   "pep",
		Generation:    fixture.Generation,
		Capabilities:  fixture.Capabilities,
	}
	cat.CatalogDigest = catalogDigest(cat)
	if cat.CatalogDigest != fixture.CatalogDigest {
		t.Fatalf("catalog digest mismatch: got %s want %s", cat.CatalogDigest, fixture.CatalogDigest)
	}
	cat.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	return cat
}

func newFixtureProxy(t *testing.T, serverURL string, cat *catalog) *Proxy {
	t.Helper()
	p, err := New(config.ProxyConfig{
		ProviderID: "grant-management", PepClientID: "pep", Origin: serverURL,
		AuthorizationMode: "forward-user",
		MaxRequestBytes:   4194304, MaxResponseBytes: 4194304,
		AuthnLimiterKey:           "k",
		PublicAuthnGlobalCapacity: 10, PublicAuthnPeerCapacity: 10,
		PublicAuthnGlobalRefill: time.Hour, PublicAuthnPeerRefill: time.Hour,
	}, serverURL, http.DefaultClient, 4)
	if err != nil {
		t.Fatal(err)
	}
	p.active = cat
	return p
}

type routeTest struct {
	name     string
	method   string
	path     string
	body     string
	wantCode int
	actionID string
	resType  string
	resID    string
}

var fixtureRoutes = []routeTest{
	{"GET organizations", http.MethodGet, "/api/v1/orgs", "", 200, "grant-management.organization.list", "service", "grant"},
	{"GET organization", http.MethodGet, "/api/v1/orgs/my-org", "", 200, "grant-management.organization.detail", "organization", "my-org"},
	{"PATCH organization", http.MethodPatch, "/api/v1/orgs/my-org", `{"name":"Renamed"}`, 200, "grant-management.organization.update", "organization", "my-org"},
	{"POST organization", http.MethodPost, "/api/v1/admin/orgs", `{"id":"new-org","name":"New","ownerUserId":"user"}`, 201, "grant-management.admin.organization.create", "platform", "grant"},
	{"PATCH provider", http.MethodPatch, "/api/v1/admin/providers/patch-data", `{"name":"Data","active":false}`, 200, "grant-management.admin.provider.update", "platform", "grant"},
	{"PUT identity binding", http.MethodPut, "/api/v1/admin/orgs/my-org/apps/app/identity-binding", `{"clientId":"existing-idp-client"}`, 200, "grant-management.admin.app.identity.bind", "platform", "grant"},
	{"PATCH app", http.MethodPatch, "/api/v1/orgs/my-org/apps/app", `{"description":null}`, 200, "grant-management.applications.update", "organization", "my-org"},
	{"PUT app active", http.MethodPut, "/api/v1/orgs/my-org/apps/app/active", `{"active":false}`, 200, "grant-management.applications.active", "organization", "my-org"},
	{"DELETE app", http.MethodDelete, "/api/v1/orgs/my-org/apps/app", "", 204, "grant-management.applications.delete", "organization", "my-org"},
	{"PATCH role", http.MethodPatch, "/api/v1/orgs/my-org/roles/role", `{"name":"Renamed"}`, 200, "grant-management.role.update", "organization", "my-org"},
	{"DELETE role", http.MethodDelete, "/api/v1/orgs/my-org/roles/role", "", 204, "grant-management.role.delete", "organization", "my-org"},
	{"GET members", http.MethodGet, "/api/v1/orgs/my-org/members", "", 200, "grant-management.members.read", "organization", "my-org"},
	{"DELETE member", http.MethodDelete, "/api/v1/orgs/my-org/members/user", "", 204, "grant-management.members.remove", "organization", "my-org"},
	{"DELETE grant", http.MethodDelete, "/api/v1/orgs/my-org/app-grants/grant1", "", 204, "grant-management.applications.grants.revoke", "organization", "my-org"},
	{"PATCH group", http.MethodPatch, "/api/v1/orgs/my-org/groups/group1", `{"description":null}`, 200, "grant-management.groups.patch", "organization", "my-org"},
	{"PATCH agreement", http.MethodPatch, "/api/v1/orgs/my-org/agreements/agreement1", `{"status":"terminated"}`, 200, "grant-management.agreements.patch", "organization", "my-org"},
	{"GET org groups", http.MethodGet, "/api/v1/orgs/my-org/groups", "", 200, "grant-management.groups.read", "organization", "my-org"},
	{"GET org groups detail", http.MethodGet, "/api/v1/orgs/my-org/groups/g1", "", 200, "grant-management.groups.detail", "organization", "my-org"},
	{"GET org groups Ops_1.team:dev", http.MethodGet, "/api/v1/orgs/Ops_1.team:dev/groups", "", 200, "grant-management.groups.read", "organization", "Ops_1.team:dev"},
	{"GET org groups consistency", http.MethodGet, "/api/v1/orgs/my-org/groups?consistency=strong", "", 200, "grant-management.groups.read", "organization", "my-org"},
	{"PUT role actions", http.MethodPut, "/api/v1/orgs/my-org/roles/admin/actions", `{"actionIds":["grant-management.groups.read"]}`, 200, "grant-management.role.actions.replace", "organization", "my-org"},
	{"DELETE binding", http.MethodDelete, "/api/v1/orgs/my-org/bindings/b1", "", 204, "grant-management.bindings.delete", "organization", "my-org"},
	{"GET admin provider actions", http.MethodGet, "/api/v1/admin/providers/patch-data/actions", "", 200, "grant-management.admin.provider.actions.read", "platform", "grant"},
	{"GET admin catalog", http.MethodGet, "/api/v1/admin/providers/patch-data/http-capability-active", "", 200, "grant-management.admin.catalog.read", "platform", "grant"},
}

func TestFullCatalogFixtureAndRoutes(t *testing.T) {
	cat := loadFixtureCatalog(t)
	if len(cat.Capabilities) != 69 {
		t.Fatalf("expected 69 capabilities, got %d", len(cat.Capabilities))
	}

	for _, rt := range fixtureRoutes {
		t.Run(rt.name, func(t *testing.T) {
			organizationID := "my-org"
			if rt.resType == "organization" {
				organizationID = rt.resID
			}
			var upstreamCalls int
			var gotMethod string
			var gotBody []byte
			var gotHeaders http.Header
			var gotRequestURI string
			allowed := true

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2/http-capabilities/decide" {
					echoDecisionHandler(t, &allowed, rt.resID, rt.actionID)(w, r)
					return
				}
				upstreamCalls++
				gotMethod = r.Method
				gotRequestURI = r.URL.RequestURI()
				gotHeaders = r.Header.Clone()
				if r.Body != nil {
					gotBody, _ = io.ReadAll(r.Body)
				}
				w.WriteHeader(rt.wantCode)
				if rt.wantCode != http.StatusNoContent {
					_, _ = w.Write([]byte(`{"ok":true}`))
				}
			}))
			defer server.Close()

			p := newFixtureProxy(t, server.URL, cat)
			token := jwtWithExtraClaims(t)
			var req *http.Request
			if rt.body != "" {
				req = httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(rt.method, rt.path, nil)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Organization-ID", organizationID)
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, req)

			if w.Code != rt.wantCode {
				t.Fatalf("status=%d want %d", w.Code, rt.wantCode)
			}
			if upstreamCalls != 1 {
				t.Fatalf("upstream calls=%d want 1", upstreamCalls)
			}
			if gotMethod != rt.method {
				t.Fatalf("upstream method=%s want %s", gotMethod, rt.method)
			}
			if rt.body != "" && string(gotBody) != rt.body {
				t.Fatalf("upstream body=%s want %s", string(gotBody), rt.body)
			}
			if gotHeaders.Get("X-Organization-ID") != organizationID {
				t.Fatalf("X-Organization-ID=%s want %s", gotHeaders.Get("X-Organization-ID"), organizationID)
			}
			if !strings.HasPrefix(gotHeaders.Get("Authorization"), "Bearer ") {
				t.Fatal("Authorization not forwarded")
			}
			if gotRequestURI != rt.path {
				t.Fatalf("upstream RequestURI=%s want %s", gotRequestURI, rt.path)
			}
		})
	}
}

func TestSpoofedGrantHeadersStripped(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var forwardedHeaders http.Header
	allowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			echoDecisionHandler(t, &allowed, "my-org", "grant-management.groups.read")(w, r)
			return
		}
		forwardedHeaders = r.Header.Clone()
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/my-org/groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	req.Header.Set("X-Grant-Master-Key", "spoofed-admin-key")
	req.Header.Set("X-Grant-App-Auth-Key", "spoofed-app-key")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	for _, name := range []string{"X-Grant-Master-Key", "X-Grant-App-Auth-Key"} {
		if forwardedHeaders.Get(name) != "" {
			t.Fatalf("spoofed header %s reached upstream", name)
		}
	}
}

func TestPDPDenyReturns403NoUpstream(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var upstreamCalls int
	allowed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			echoDecisionHandler(t, &allowed, "my-org", "grant-management.groups.read")(w, r)
			return
		}
		upstreamCalls++
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/my-org/groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", w.Code)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls=%d want 0", upstreamCalls)
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	cat := loadFixtureCatalog(t)
	p := newFixtureProxy(t, "http://unused", cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/unknown/path", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "org")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", w.Code)
	}
}

func TestEchoPDPRequestBindingFields(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var gotDecisionBody map[string]any
	allowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			_ = json.NewDecoder(r.Body).Decode(&gotDecisionBody)
			echoDecisionMap(t, &allowed, gotDecisionBody, "my-org", "grant-management.groups.read")(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/my-org/groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	for _, field := range []string{"providerId", "pepClientId", "catalogGeneration", "catalogDigest", "capabilityId", "capabilityVersion", "contractDigest", "method", "canonicalPath", "canonicalQueryDigest", "forwardedHeaderDigest", "bodyDigest", "bodyLength", "providerCredentialDigest", "requestBinding"} {
		if _, ok := gotDecisionBody[field]; !ok {
			t.Fatalf("missing PDP request field: %s", field)
		}
	}
	cred := gotDecisionBody["providerCredential"].(map[string]any)
	if cred["subject"] != "user-1" {
		t.Fatalf("providerSubject=%v want user-1", cred["subject"])
	}
	if cred["audience"] != "client-1" {
		t.Fatalf("providerAudience=%v want client-1", cred["audience"])
	}
}

func TestMaxRequestResponse4MiB(t *testing.T) {
	cat := loadFixtureCatalog(t)
	for _, c := range cat.Capabilities {
		if c.Response.MaxBytes != 4194304 {
			t.Fatalf("capability %s response.maxBytes=%d want 4194304", c.CapabilityID, c.Response.MaxBytes)
		}
		if c.Request.Body == "json" && c.Request.MaxBytes != 2097152 {
			t.Fatalf("capability %s request.maxBytes=%d want 2097152", c.CapabilityID, c.Request.MaxBytes)
		}
	}
}

func TestAllManagementCapabilitiesDigestsValid(t *testing.T) {
	cat := loadFixtureCatalog(t)
	if len(cat.Capabilities) != 69 {
		t.Fatalf("expected 69, got %d", len(cat.Capabilities))
	}
	for _, c := range cat.Capabilities {
		if c.ContractDigest != capabilityDigest(c) {
			t.Fatalf("capability %s contract digest mismatch", c.CapabilityID)
		}
	}
	if cat.CatalogDigest != catalogDigest(cat) {
		t.Fatal("catalog digest mismatch")
	}
}

func TestGroupsQueryRejections(t *testing.T) {
	cat := loadFixtureCatalog(t)
	token := jwtWithExtraClaims(t)

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"unknown query param", http.MethodGet, "/api/v1/orgs/my-org/groups?unknown=x"},
		{"duplicate consistency", http.MethodGet, "/api/v1/orgs/my-org/groups?consistency=strong&consistency=weak"},
		{"POST with consistency", http.MethodPost, "/api/v1/orgs/my-org/groups?consistency=strong"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2/http-capabilities/decide" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				upstreamCalls++
			}))
			defer server.Close()
			p := newFixtureProxy(t, server.URL, cat)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.method == http.MethodPost {
				req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"id":"g1","name":"Test"}`))
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Organization-ID", "my-org")
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d want 422", w.Code)
			}
			if upstreamCalls != 0 {
				t.Fatalf("upstream calls=%d want 0", upstreamCalls)
			}
		})
	}
}

func TestIfMatchForwarding(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var gotHeaders http.Header
	allowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			echoDecisionHandler(t, &allowed, "my-org", "grant-management.role.actions.replace")(w, r)
			return
		}
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/orgs/my-org/roles/admin/actions", strings.NewReader(`{"actionIds":["grant-management.groups.read"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	req.Header.Set("If-Match", `"abc123"`)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if gotHeaders.Get("If-Match") != `"abc123"` {
		t.Fatalf("If-Match not forwarded, got %q", gotHeaders.Get("If-Match"))
	}
}

func TestETagResponseForwarding(t *testing.T) {
	cat := loadFixtureCatalog(t)
	allowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			echoDecisionHandler(t, &allowed, "my-org", "grant-management.role.actions.replace")(w, r)
			return
		}
		w.Header().Set("ETag", `"v1-abc123"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/orgs/my-org/roles/admin/actions", strings.NewReader(`{"actionIds":["grant-management.groups.read"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if w.Header().Get("ETag") != `"v1-abc123"` {
		t.Fatalf("ETag not forwarded, got %q", w.Header().Get("ETag"))
	}
}

func TestUpstream412PreconditionFailed(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var upstreamCalls int
	allowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			echoDecisionHandler(t, &allowed, "my-org", "grant-management.role.actions.replace")(w, r)
			return
		}
		upstreamCalls++
		w.Header().Set("ETag", `"v1-stale"`)
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = w.Write([]byte(`{"error":"precondition failed"}`))
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/orgs/my-org/roles/admin/actions", strings.NewReader(`{"actionIds":["grant-management.groups.read"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	req.Header.Set("If-Match", `"v1-different"`)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("status=%d want 412", w.Code)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls=%d want 1", upstreamCalls)
	}
	if w.Header().Get("ETag") != `"v1-stale"` {
		t.Fatalf("ETag not forwarded, got %q", w.Header().Get("ETag"))
	}
}

func TestUpstream428PreconditionRequired(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var upstreamCalls int
	allowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			echoDecisionHandler(t, &allowed, "my-org", "grant-management.applications.consent.replace")(w, r)
			return
		}
		upstreamCalls++
		w.WriteHeader(http.StatusPreconditionRequired)
		_, _ = w.Write([]byte(`{"error":"precondition required"}`))
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/orgs/my-org/apps/my-app/consent", strings.NewReader(`{"consent":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("status=%d want 428", w.Code)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls=%d want 1", upstreamCalls)
	}
}

func TestPrivateOpsDenial(t *testing.T) {
	cat := loadFixtureCatalog(t)
	token := jwtWithExtraClaims(t)

	opsPaths := []struct{ method, path string }{
		{"POST", "/ops/migrations/patch-data-authority"},
		{"PUT", "/ops/providers/patch-data/enforcers/pep1"},
		{"GET", "/ops/backups"},
		{"POST", "/ops/backups"},
		{"POST", "/api/v1/admin/bootstrap/owner"},
		{"GET", "/api/v1/admin/backups/s3"},
	}
	for _, endpoint := range opsPaths {
		t.Run(endpoint.method+endpoint.path, func(t *testing.T) {
			var upstreamCalls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
			}))
			defer server.Close()
			p := newFixtureProxy(t, server.URL, cat)
			req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Organization-ID", "my-org")
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status=%d want 404", w.Code)
			}
			if upstreamCalls != 0 {
				t.Fatalf("upstream calls=%d want 0", upstreamCalls)
			}
		})
	}
}

func TestConsentCreationIfNoneMatch(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var gotHeaders http.Header
	allowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			echoDecisionHandler(t, &allowed, "my-org", "grant-management.applications.consent.replace")(w, r)
			return
		}
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"consent":true}`))
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/orgs/my-org/apps/my-app/consent", strings.NewReader(`{"consent":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	req.Header.Set("If-None-Match", "*")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d", w.Code)
	}
	if gotHeaders.Get("If-None-Match") != "*" {
		t.Fatalf("If-None-Match not forwarded, got %q", gotHeaders.Get("If-None-Match"))
	}
}

func TestConsentEditIfMatch(t *testing.T) {
	cat := loadFixtureCatalog(t)
	var gotHeaders http.Header
	allowed := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/http-capabilities/decide" {
			echoDecisionHandler(t, &allowed, "my-org", "grant-management.applications.consent.replace")(w, r)
			return
		}
		gotHeaders = r.Header.Clone()
		w.Header().Set("ETag", `"v2-updated"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"consent":true}`))
	}))
	defer server.Close()

	p := newFixtureProxy(t, server.URL, cat)
	token := jwtWithExtraClaims(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/orgs/my-org/apps/my-app/consent", strings.NewReader(`{"consent":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", "my-org")
	req.Header.Set("If-Match", `"v1-current"`)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if gotHeaders.Get("If-Match") != `"v1-current"` {
		t.Fatalf("If-Match not forwarded, got %q", gotHeaders.Get("If-Match"))
	}
	if w.Header().Get("ETag") != `"v2-updated"` {
		t.Fatalf("ETag not forwarded, got %q", w.Header().Get("ETag"))
	}
}
