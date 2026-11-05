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

func TestGoauthyUserProfileRejectsInexactClaims(t *testing.T) {
	cfg := config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://issuer.example", GoauthyUserClientID: "fixture-client", GoauthyUserResourceAudience: "resource", GoauthyApplicationID: "legacy-app"}
	for _, fragment := range []string{
		`"aud":["fixture-client","resource","extra"]`,
		`"aud":["fixture-client","fixture-client"]`,
		`"aud":["resource","resource"]`,
		`"aud":["resource"]`, `"aud":"resource"`, `"aud":null`, `"aud":[null,"resource"]`,
		`"aud":["fixture-client",1]`, `"aud":["wrong","resource"]`,
		`"aud":["fixture-client","resource"],"azp":"wrong"`,
		`"aud":["fixture-client","resource"],"azp":null`,
		`"aud":["fixture-client","resource"],"azp":1`,
		`"aud":["fixture-client","resource"],"iss":"https://wrong.example"`,
		`"aud":["fixture-client","resource"],"iss":null`,
	} {
		// Replacing canonical claims builds malformed vectors without duplicate keys.
		claims := map[string]json.RawMessage{"sub": json.RawMessage(`"fixture-user"`), "iss": json.RawMessage(`"https://issuer.example"`), "azp": json.RawMessage(`"fixture-client"`)}
		var overrides map[string]json.RawMessage
		if json.Unmarshal([]byte(`{`+fragment+`}`), &overrides) != nil {
			t.Fatal("invalid test vector")
		}
		for key, value := range overrides {
			claims[key] = value
		}
		payload, _ := json.Marshal(claims)
		r := httptest.NewRequest("GET", "/items", nil)
		r.Header.Set("Authorization", "Bearer "+goauthyJWT(t, string(payload)))
		r.Header.Set("X-Organization-ID", "fixture-org")
		if _, _, _, _, err := userBearerIdentity(r, cfg, false); err == nil {
			t.Fatal("inexact profile claims accepted")
		}
	}
	for _, payload := range []string{
		`{"sub":"fixture-user","aud":["fixture-client","resource"],"iss":"https://issuer.example"}`,
		`{"sub":"fixture-user","aud":["fixture-client","resource"],"azp":"fixture-client"}`,
		`{"sub":"fixture-user","aud":["fixture-client","resource"],"ISS":"https://issuer.example","azp":"fixture-client"}`,
		`{"sub":"fixture-user","aud":["fixture-client","resource"],"iss":"https://issuer.example","AZP":"fixture-client"}`,
		`{"sub":"fixture-user","AUD":["fixture-client","resource"],"iss":"https://issuer.example","azp":"fixture-client"}`,
		`{"sub":"fixture-user","aud":["fixture-client","resource"],"iss":"https://issuer.example","azp":"fixture-client","azp":"fixture-client"}`,
	} {
		r := httptest.NewRequest("GET", "/items", nil)
		r.Header.Set("Authorization", "Bearer "+goauthyJWT(t, payload))
		r.Header.Set("X-Organization-ID", "fixture-org")
		if _, _, _, _, err := userBearerIdentity(r, cfg, false); err == nil {
			t.Fatal("missing, aliased, or duplicate profile claim accepted")
		}
	}
	legacy := httptest.NewRequest("GET", "/items", nil)
	legacy.Header.Set("Authorization", "Bearer "+goauthyJWT(t, `{"sub":"fixture-user","aud":["extra","resource"],"azp":"wrong"}`))
	legacy.Header.Set("X-Organization-ID", "fixture-org")
	if _, _, _, audience, err := bearerIdentity(legacy, cfg); err != nil || audience != "legacy-app" {
		t.Fatal("user profile changed legacy application semantics")
	}
}

// A stub PDP checks transport and hint binding; Grant online authentication is separate.
func TestGoauthyUserProfileConfigAndHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, audience, override, value string
		profile, allow                  bool
	}{
		{"configured pair", `["fixture-client","resource"]`, "", "", true, true},
		{"reverse pair", `["resource","fixture-client"]`, "", "", true, true},
		{"extra audience", `["fixture-client","resource","extra"]`, "", "", true, false},
		{"duplicate audience", `["fixture-client","fixture-client"]`, "", "", true, false},
		{"no singleton fallback", `["resource"]`, "", "", true, false},
		{"default rejects multiple", `["fixture-client","resource"]`, "", "", false, false},
		{"default singleton", `["resource"]`, "", "", false, true},
		{"wrong client", `["fixture-client","resource"]`, "azp", `"wrong"`, true, false},
		{"null client", `["fixture-client","resource"]`, "azp", `null`, true, false},
		{"missing client", `["fixture-client","resource"]`, "azp", "", true, false},
		{"wrong issuer", `["fixture-client","resource"]`, "iss", `"https://wrong.example"`, true, false},
		{"null issuer", `["fixture-client","resource"]`, "iss", `null`, true, false},
		{"missing issuer", `["fixture-client","resource"]`, "iss", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const path = "/api/v1/admin/providers/fixture-provider/http-capability-active"
			claims := map[string]json.RawMessage{"sub": json.RawMessage(`"fixture-user"`), "iss": json.RawMessage(`"https://issuer.example"`), "azp": json.RawMessage(`"fixture-client"`), "aud": json.RawMessage(tc.audience)}
			if tc.override != "" {
				if tc.value == "" {
					delete(claims, tc.override)
				} else {
					claims[tc.override] = json.RawMessage(tc.value)
				}
			}
			payload, _ := json.Marshal(claims)
			auth := "Bearer " + goauthyJWT(t, string(payload))
			cap := organizationPolicyCapability("required")
			cap.Method, cap.PathTemplate = "GET", path
			cap.ContractDigest = capabilityDigest(cap)
			cat := organizationPolicyCatalog(cap)
			cat.AuthorizationMode, cat.PepPolicyRevision = "user", 1
			var catalogs, decisions, upstreams atomic.Int64
			checkHeaders := func(r *http.Request) {
				if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Authorization") != auth || r.Header.Get("X-Organization-ID") != "fixture-org" {
					t.Error("original authorization headers changed")
				}
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreams.Add(1)
				checkHeaders(r)
				_, _ = io.WriteString(w, `{"ok":true}`)
			}))
			defer origin.Close()
			grant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Grant-App-Auth-Key") != "fixture-key" {
					t.Error("missing private Grant credential")
				}
				if r.URL.Path == "/api/v2/http-capabilities/catalog/"+cat.ProviderID {
					catalogs.Add(1)
					_ = json.NewEncoder(w).Encode(cat)
					return
				}
				decisions.Add(1)
				checkHeaders(r)
				var in map[string]any
				if json.NewDecoder(r.Body).Decode(&in) != nil {
					t.Error("invalid decision wire")
					return
				}
				credential, ok := in["providerCredential"].(map[string]any)
				if !ok || credential["subject"] != "goauthy:https://issuer.example/fixture-user" || credential["audience"] != "resource" || in["wireVersion"] != float64(2) || in["pepPolicyRevision"] != float64(1) {
					t.Error("user hint or version/revision changed")
				}
				allow := true
				recorded := httptest.NewRecorder()
				echoDecisionMap(t, &allow, in, "self", "identity.enroll")(recorded, r)
				var out map[string]any
				if json.Unmarshal(recorded.Body.Bytes(), &out) != nil {
					t.Error("invalid fixture decision")
					return
				}
				out["wireVersion"], out["pepPolicyRevision"] = 2, 1
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer grant.Close()
			for _, entry := range os.Environ() {
				name, _, _ := strings.Cut(entry, "=")
				if strings.HasPrefix(name, "EXPOSURE_") {
					t.Setenv(name, "")
				}
			}
			for key, value := range map[string]string{
				"EXPOSURE_PROXY_ENABLED": "true", "EXPOSURE_GRANT_LEARNER_URL": grant.URL,
				"EXPOSURE_PROVIDER_ORIGIN": origin.URL, "EXPOSURE_PROVIDER_ID": cat.ProviderID,
				"EXPOSURE_PEP_CLIENT_ID": cat.PepClientID, "EXPOSURE_EXPECTED_CATALOG_DIGEST": cat.CatalogDigest,
				"EXPOSURE_GRANT_APP_AUTH_KEY": "fixture-key", "EXPOSURE_AUTHN_LIMITER_KEY": "fixture-limiter",
				"EXPOSURE_PROVIDER_AUTHORIZATION_MODE": "forward-user", "EXPOSURE_CREDENTIAL_MODE": "goauthy",
				"EXPOSURE_GOAUTHY_ISSUER": "https://issuer.example",
			} {
				t.Setenv(key, value)
			}
			if tc.profile {
				t.Setenv("EXPOSURE_GOAUTHY_USER_CLIENT_ID", "fixture-client")
				t.Setenv("EXPOSURE_GOAUTHY_USER_RESOURCE_AUDIENCE", "resource")
			}
			cfg, err := config.Load()
			if err != nil {
				t.Fatal("fixture configuration rejected")
			}
			if tc.profile && tc.allow {
				for _, invalidResource := range []string{"", "fixture-client"} {
					t.Setenv("EXPOSURE_GOAUTHY_USER_RESOURCE_AUDIENCE", invalidResource)
					if _, err := config.Load(); err == nil {
						t.Fatal("partial or equal profile configuration accepted at startup")
					}
				}
				t.Setenv("EXPOSURE_GOAUTHY_USER_RESOURCE_AUDIENCE", "resource")
			}
			p, err := New(cfg.Proxy, cfg.LearnerURL, grant.Client(), cfg.MaxConcurrent)
			if err != nil || p.Refresh(context.Background()) != nil {
				t.Fatal("fixture user catalog rejected")
			}
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", auth)
			r.Header.Set("X-Organization-ID", "fixture-org")
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, r)
			wantStatus, wantCalls := 401, int64(0)
			if tc.allow {
				wantStatus, wantCalls = 200, 1
			}
			if w.Code != wantStatus || catalogs.Load() != 1 || decisions.Load() != wantCalls || upstreams.Load() != wantCalls {
				t.Fatalf("status=%d catalog=%d PDP=%d upstream=%d", w.Code, catalogs.Load(), decisions.Load(), upstreams.Load())
			}
			if !tc.allow && strings.Contains(w.Body.String(), `"ok"`) {
				t.Fatal("rejected request exposed business bytes")
			}
		})
	}
}
