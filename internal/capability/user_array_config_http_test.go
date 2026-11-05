package capability

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mrchypark/exposure/internal/config"
)

// These HTTP fixtures distinguish local parsing from a PDP 401; they do not
// prove live Goauthy authentication or real Grant authorization.
func TestUserAudienceArrayWithoutApplicationConfigHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, audience              string
		legacy, pdpUnauthorized     bool
		status, decisions, upstream int
	}{
		{name: "single audience array", audience: `["resource"]`, status: 200, decisions: 1, upstream: 1},
		{name: "single audience string", audience: `"resource"`, status: 200, decisions: 1, upstream: 1},
		{name: "PDP unauthorized", audience: `["resource"]`, pdpUnauthorized: true, status: 401, decisions: 1},
		{name: "local multiple audiences", audience: `["resource","other"]`, status: 401},
		{name: "local missing audience", audience: `null`, status: 401},
		{name: "legacy requires application config", audience: `["resource"]`, legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const path = "/api/v1/admin/providers/fixture-provider/http-capability-active"
			const organization = "fixture-org"
			const appKey = "fixture-app-key"
			auth := "Bearer " + goauthyJWT(t, `{"iss":"https://issuer.example","sub":"fixture-user","aud":`+tc.audience+`,"azp":"fixture-client"}`)
			cap := organizationPolicyCapability("required")
			cap.Method = http.MethodGet
			cap.PathTemplate = "/api/v1/admin/providers/{provider}/http-capability-active"
			cap.CapabilityID = "management.catalog.read"
			action := "grant.http.catalog.read"
			cap.ActionID = &action
			cap.Resource = &resource{Type: "provider", ID: extractor{Kind: "pathSegment", Name: "provider", Format: "asciiToken"}}
			cap.ContractDigest = capabilityDigest(cap)
			cat := organizationPolicyCatalog(cap)
			cat.Generation = 177
			if !tc.legacy {
				cat.AuthorizationMode, cat.PepPolicyRevision = "user", 1
			}
			cat.CatalogDigest = catalogDigest(cat)
			var catalogs, decisions, upstreams atomic.Int64
			checkUserHeaders := func(r *http.Request) {
				if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Authorization") != auth || r.Header.Get("X-Organization-ID") != organization {
					t.Error("original credential or organization header changed")
				}
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreams.Add(1)
				checkUserHeaders(r)
				if r.Method != http.MethodGet || r.URL.Path != path {
					t.Error("upstream method or path changed")
				}
				_, _ = io.WriteString(w, `{"catalog":true}`)
			}))
			defer origin.Close()
			grant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Grant-App-Auth-Key") != appKey {
					t.Error("server-owned Grant authentication missing")
				}
				switch r.URL.Path {
				case "/api/v2/http-capabilities/catalog/" + cat.ProviderID:
					catalogs.Add(1)
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
						t.Error("runtime catalog fetch used user authentication or wrong method")
					}
					_ = json.NewEncoder(w).Encode(cat)
				case "/api/v2/http-capabilities/decide":
					decisions.Add(1)
					checkUserHeaders(r)
					var in map[string]any
					if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&in) != nil {
						t.Error("invalid decision request")
						w.WriteHeader(500)
						return
					}
					credential, ok := in["providerCredential"].(map[string]any)
					if !ok || credential["subject"] != "goauthy:https://issuer.example/fixture-user" || credential["audience"] != "resource" || in["wireVersion"] != float64(2) || in["pepPolicyRevision"] != float64(1) {
						t.Error("user identity hint or policy binding changed")
					}
					if tc.pdpUnauthorized {
						w.WriteHeader(401)
						_, _ = io.WriteString(w, `{"error":"fixture-private-detail"}`)
						return
					}
					allow := true
					recorder := httptest.NewRecorder()
					echoDecisionMap(t, &allow, in, "fixture-provider", action)(recorder, r)
					var out map[string]any
					if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
						t.Error("invalid fixture decision")
						w.WriteHeader(500)
						return
					}
					out["wireVersion"], out["pepPolicyRevision"] = 2, 1
					_ = json.NewEncoder(w).Encode(out)
				default:
					t.Error("unexpected Grant path")
					w.WriteHeader(404)
				}
			}))
			defer grant.Close()
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if strings.HasPrefix(key, "EXPOSURE_") {
					t.Setenv(key, "")
				}
			}
			for key, value := range map[string]string{
				"EXPOSURE_PROXY_ENABLED":               "true",
				"EXPOSURE_GRANT_LEARNER_URL":           grant.URL,
				"EXPOSURE_PROVIDER_ORIGIN":             origin.URL,
				"EXPOSURE_PROVIDER_ID":                 cat.ProviderID,
				"EXPOSURE_PEP_CLIENT_ID":               cat.PepClientID,
				"EXPOSURE_EXPECTED_CATALOG_DIGEST":     cat.CatalogDigest,
				"EXPOSURE_GRANT_APP_AUTH_KEY":          appKey,
				"EXPOSURE_AUTHN_LIMITER_KEY":           "fixture-limiter-key",
				"EXPOSURE_PROVIDER_AUTHORIZATION_MODE": "forward-user",
				"EXPOSURE_CREDENTIAL_MODE":             "goauthy",
				"EXPOSURE_GOAUTHY_ISSUER":              "https://issuer.example",
				"EXPOSURE_GOAUTHY_APPLICATION_ID":      "",
			} {
				t.Setenv(key, value)
			}
			cfg, err := config.Load()
			if err != nil || cfg.Proxy.GoauthyApplicationID != "" {
				t.Fatal("configuration without application ID failed")
			}
			p, err := New(cfg.Proxy, cfg.LearnerURL, grant.Client(), cfg.MaxConcurrent)
			if err != nil {
				t.Fatal(err)
			}
			err = p.Refresh(context.Background())
			if tc.legacy {
				if err == nil || p.Ready() || catalogs.Load() != 1 || decisions.Load() != 0 || upstreams.Load() != 0 {
					t.Fatal("legacy catalog without application ID did not fail closed")
				}
				return
			}
			if err != nil || !p.Ready() {
				t.Fatal("user catalog without application ID failed refresh")
			}
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Header.Set("Authorization", auth)
			r.Header.Set("X-Organization-ID", organization)
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || catalogs.Load() != 1 || decisions.Load() != int64(tc.decisions) || upstreams.Load() != int64(tc.upstream) {
				t.Fatalf("status=%d catalog=%d PDP=%d upstream=%d", w.Code, catalogs.Load(), decisions.Load(), upstreams.Load())
			}
			if tc.status == 200 {
				if w.Body.String() != `{"catalog":true}` {
					t.Error("business response changed")
				}
			} else if w.Body.String() != `{"schemaVersion":1,"errorCode":"unauthorized"}` {
				t.Error("401 leaked provider detail or changed bounded error envelope")
			}
		})
	}
}
