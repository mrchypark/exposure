package capability

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

func organizationPolicyCapability(policy string) capability {
	action := "identity.enroll"
	c := capability{CapabilityID: "enroll", Version: 1, Enabled: true, AccessMode: "authorized", Method: "POST", PathTemplate: "/accounts/enroll", ActionID: &action, Resource: &resource{Type: "workspace", ID: extractor{Kind: "constant", Value: "self"}}, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "none", Authorization: "forward-user", ForwardHeaders: []string{"x-organization-id"}}, Response: responsePolicy{MaxBytes: 1024, Redirects: "deny"}, OrganizationContext: policy}
	c.ContractDigest = capabilityDigest(c)
	return c
}

func organizationPolicyCatalog(c capability) *catalog {
	cat := &catalog{SchemaVersion: 1, ProviderID: "independent-identity", PepClientID: "enrollment-pep", Generation: 1, Capabilities: []capability{c}, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
	cat.CatalogDigest = catalogDigest(cat)
	return cat
}

func TestOrganizationContextIsGenericAndDecisionBound(t *testing.T) {
	for _, tc := range []struct {
		name, policy, credential    string
		orgs                        []string
		allow, tamper               bool
		status, decisions, upstream int
	}{
		{name: "arbitrary provider orgless allow", policy: "optional", credential: "valid", allow: true, status: 200, decisions: 1, upstream: 1},
		{name: "arbitrary provider orgless deny", policy: "optional", credential: "valid", status: 403, decisions: 1},
		{name: "optional supplied organization", policy: "optional", credential: "valid", orgs: []string{"tenant-one"}, allow: true, status: 200, decisions: 1, upstream: 1},
		{name: "supplied organization denial", policy: "optional", credential: "valid", orgs: []string{"tenant-one"}, status: 403, decisions: 1},
		{name: "bound decision tamper", policy: "optional", credential: "valid", allow: true, tamper: true, status: 502, decisions: 1},
		{name: "omitted policy requires organization", credential: "valid", allow: true, status: 401},
		{name: "explicit required needs organization", policy: "required", credential: "valid", allow: true, status: 401},
		{name: "required supplied", policy: "required", credential: "valid", orgs: []string{"tenant-one"}, allow: true, status: 200, decisions: 1, upstream: 1},
		{name: "missing bearer", policy: "optional", status: 401},
		{name: "malformed bearer", policy: "optional", credential: "malformed", status: 401},
		{name: "optional empty organization", policy: "optional", credential: "valid", orgs: []string{""}, status: 401},
		{name: "optional duplicate organization", policy: "optional", credential: "valid", orgs: []string{"one", "two"}, status: 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var decisions, upstream atomic.Int64
			expectedOrg := ""
			if len(tc.orgs) == 1 {
				expectedOrg = tc.orgs[0]
			}
			checkOrg := func(r *http.Request) {
				if r.Header.Get("X-Organization-ID") != expectedOrg {
					t.Error("organization changed")
				}
				if expectedOrg == "" && len(r.Header.Values("X-Organization-ID")) != 0 {
					t.Error("absent organization became an empty header")
				}
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstream.Add(1)
				checkOrg(r)
				if r.URL.Path != "/accounts/enroll" || r.Method != "POST" {
					t.Error("upstream request changed")
				}
				_, _ = io.WriteString(w, `{"enrolled":true}`)
			}))
			defer origin.Close()
			cat := organizationPolicyCatalog(organizationPolicyCapability(tc.policy))
			grant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/v2/http-capabilities/catalog/") {
					_ = json.NewEncoder(w).Encode(cat)
					return
				}
				decisions.Add(1)
				checkOrg(r)
				var in map[string]any
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				if tc.tamper {
					in["contractDigest"] = "sha256:" + strings.Repeat("f", 64)
				}
				allow := tc.allow
				echoDecisionMap(t, &allow, in, "self", "identity.enroll")(w, r)
			}))
			defer grant.Close()
			p, err := New(config.ProxyConfig{ProviderID: cat.ProviderID, PepClientID: cat.PepClientID, Origin: origin.URL, ExpectedCatalogDigest: cat.CatalogDigest, AuthorizationMode: "forward-user", MaxRequestBytes: 1024, MaxResponseBytes: 1024}, grant.URL, origin.Client(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/accounts/enroll", nil)
			switch tc.credential {
			case "valid":
				req.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
			case "malformed":
				req.Header.Set("Authorization", "Bearer invalid")
			}
			for _, org := range tc.orgs {
				req.Header.Add("X-Organization-ID", org)
			}
			out := httptest.NewRecorder()
			p.Handler().ServeHTTP(out, req)
			if out.Code != tc.status || decisions.Load() != int64(tc.decisions) || upstream.Load() != int64(tc.upstream) {
				t.Fatalf("status=%d decisions=%d upstream=%d", out.Code, decisions.Load(), upstream.Load())
			}
		})
	}
}

func TestOldManagementTupleWithoutPolicyRequiresOrganization(t *testing.T) {
	cat := loadFixtureCatalog(t)
	for i := range cat.Capabilities {
		cat.Capabilities[i].OrganizationContext = ""
		cat.Capabilities[i].ContractDigest = capabilityDigest(cat.Capabilities[i])
	}
	cat.CatalogDigest = catalogDigest(cat)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	p := newFixtureProxy(t, server.URL, cat)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/me", ""}, {"POST", "/api/v1/me/ensure", ""}, {"GET", "/api/v1/orgs", ""}, {"POST", "/api/v1/orgs", `{"id":"new-org","name":"New"}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		out := httptest.NewRecorder()
		p.Handler().ServeHTTP(out, req)
		if out.Code != 401 || calls.Load() != 0 {
			t.Fatalf("hidden management fallback: %s status=%d calls=%d", tc.path, out.Code, calls.Load())
		}
	}
}

func TestOrganizationContextStrictDecodingAndValidation(t *testing.T) {
	c := organizationPolicyCapability("")
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimSuffix(string(b), "}")
	for _, field := range []string{
		`"organizationContext":null`, `"organizationContext":""`, `"organizationContext":"none"`, `"organizationContext":"OPTIONAL"`, `"organizationContext":true`, `"organizationContext":{}`,
		`"OrganizationContext":"optional"`, `"organizationcontext":"optional"`,
		`"organizationContext":"required","organizationContext":"optional"`,
		`"organizationContext":"optional","OrganizationContext":"required"`,
	} {
		var decoded capability
		if err := strictJSON([]byte(base+","+field+"}"), &decoded); err == nil {
			t.Errorf("malformed policy accepted: %s", field)
		}
	}
	for _, policy := range []string{"", "required", "optional"} {
		c := organizationPolicyCapability(policy)
		b, _ := json.Marshal(c)
		var decoded capability
		if err := strictJSON(b, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := validateCapability(decoded); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"public_authn", "unknown"} {
		c := organizationPolicyCapability("optional")
		c.AccessMode = mode
		if err := validateCapability(c); err == nil {
			t.Fatal("organization policy accepted for non-authorized capability")
		}
	}
	c.OrganizationContext = "unsupported"
	if err := validateCapability(c); err == nil {
		t.Fatal("unsupported in-memory policy accepted")
	}
}

func TestOrganizationContextPolicyIsDigestBound(t *testing.T) {
	original := organizationPolicyCatalog(organizationPolicyCapability("required"))
	for _, recomputeContract := range []bool{false, true} {
		t.Run(map[bool]string{false: "contract tamper", true: "catalog tamper"}[recomputeContract], func(t *testing.T) {
			modified := *original
			modified.Capabilities = append([]capability(nil), original.Capabilities...)
			modified.Capabilities[0].OrganizationContext = "optional"
			if recomputeContract {
				modified.Capabilities[0].ContractDigest = capabilityDigest(modified.Capabilities[0])
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(modified) }))
			defer server.Close()
			p, err := New(config.ProxyConfig{ProviderID: original.ProviderID, PepClientID: original.PepClientID, Origin: server.URL, ExpectedCatalogDigest: original.CatalogDigest, AuthorizationMode: "forward-user", MaxResponseBytes: 1024}, server.URL, server.Client(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Refresh(context.Background()); err == nil || p.Ready() {
				t.Fatal("tampered organization policy accepted")
			}
		})
	}
	omitted := organizationPolicyCapability("")
	explicit := organizationPolicyCapability("required")
	optional := organizationPolicyCapability("optional")
	if omitted.ContractDigest == explicit.ContractDigest || explicit.ContractDigest == optional.ContractDigest {
		t.Fatal("explicit organization policy not included in contract digest")
	}
}

func TestOrganizationContextIndependentDigestVector(t *testing.T) {
	// Independently calculated using jq -cS + openssl dgst -sha256 for the
	// contract, and typed property order + openssl for the generation. This is
	// a local encoding vector, not proof of interoperability with Grant.
	c := organizationPolicyCapability("optional")
	if c.ContractDigest != "sha256:deb6a2af70b0bd74280eca93950cf64e52020ce6ad9e213c00f95bfddac5a7ff" {
		t.Fatal("organization contract encoding changed")
	}
	if organizationPolicyCatalog(c).CatalogDigest != "sha256:0cc54476776800f44815592527d854ec4791c7a997d7c335ffd0814807960676" {
		t.Fatal("organization generation encoding changed")
	}
}

func TestOptionalBatchCannotWeakenChildOrganizationPolicy(t *testing.T) {
	c := batchTestCatalog()
	c.Capabilities[3].OrganizationContext = "optional"
	if err := validateBatchCatalog(c); err == nil {
		t.Fatal("optional batch admitted required-org children")
	}
	for i := range c.Capabilities {
		c.Capabilities[i].OrganizationContext = "optional"
	}
	if err := validateBatchCatalog(c); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"", "required"} {
		c.Capabilities[1].OrganizationContext = policy
		if err := validateBatchCatalog(c); err == nil {
			t.Fatal("optional batch admitted required-org upsert target")
		}
	}
	c.Capabilities[3].OrganizationContext = "required"
	if err := validateBatchCatalog(c); err != nil {
		t.Fatal("required parent rejected stricter organization boundary", err)
	}
}

func TestOptionalOrganizationRejectsUnsupportedScopedCombinations(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*capability)
	}{
		{"record scope", func(c *capability) { c.RecordScope = &recordScopePolicy{} }},
		{"response references", func(c *capability) { c.ResponseAuthorization = &responseAuthorizationPolicy{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := organizationPolicyCapability("optional")
			tc.configure(&c)
			if err := validateCapability(c); err == nil || !strings.Contains(err.Error(), "require organization context") {
				t.Fatalf("unsupported optional combination accepted: %v", err)
			}
		})
	}
	// Existing complete response-reference contracts keep their required-org path.
	c := responseTestCatalog().Capabilities[0]
	if err := validateCapability(c); err != nil {
		t.Fatal(err)
	}
	c.OrganizationContext = "required"
	if err := validateCapability(c); err != nil {
		t.Fatal(err)
	}
}
