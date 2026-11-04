package capability

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/exposure/internal/config"
)

func TestUserCatalogPolicyClosedAndLegacyDigestUnchanged(t *testing.T) {
	for _, fragment := range []string{
		`"authorizationMode":"user"`, `"pepPolicyRevision":1`,
		`"authorizationMode":null,"pepPolicyRevision":1`,
		`"authorizationMode":"application","pepPolicyRevision":1`,
		`"authorizationMode":"user","pepPolicyRevision":0`,
		`"authorizationMode":"user","pepPolicyRevision":null`,
		`"authorizationMode":"user","pepPolicyRevision":9223372036854775808`,
		`"authorizationMode":"user","pepPolicyRevision":1.5`,
		`"AuthorizationMode":"user","pepPolicyRevision":1`,
	} {
		var c catalog
		if strictJSON([]byte(`{`+fragment+`}`), &c) == nil {
			t.Fatalf("invalid policy accepted: %s", fragment)
		}
	}
	c := organizationPolicyCatalog(organizationPolicyCapability(""))
	before := catalogDigest(c)
	b, err := json.Marshal(c)
	if err != nil || strings.Contains(string(b), "authorizationMode") || strings.Contains(string(b), "pepPolicyRevision") {
		t.Fatalf("legacy envelope changed: %s %v", b, err)
	}
	c.AuthorizationMode, c.PepPolicyRevision = "user", 9223372036854775807
	b, err = json.Marshal(c)
	var decoded catalog
	if err != nil || strictJSON(b, &decoded) != nil || decoded.PepPolicyRevision != c.PepPolicyRevision || catalogDigest(&decoded) != before {
		t.Fatal("user envelope changed catalog digest or lost int64 precision")
	}
}

func TestUserJWTRequiresExactlyOneAudience(t *testing.T) {
	cfg := config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://issuer.example"}
	for _, tc := range []struct {
		aud   string
		valid bool
	}{
		{`"resource"`, true}, {`["resource"]`, true},
		{`null`, false}, {`[]`, false}, {`["resource","other"]`, false},
		{`[null]`, false}, {`1`, false}, {`""`, false}, {`" resource"`, false},
	} {
		r := httptest.NewRequest("GET", "/items/one", nil)
		r.Header.Set("Authorization", "Bearer "+goauthyJWT(t, `{"sub":"user","aud":`+tc.aud+`,"azp":"ignored"}`))
		r.Header.Set("X-Organization-ID", "org")
		_, _, subject, audience, err := userBearerIdentity(r, cfg, false)
		if (err == nil) != tc.valid || tc.valid && (subject != "goauthy:https://issuer.example/user" || audience != "resource") {
			t.Fatalf("aud=%s subject=%q audience=%q err=%v", tc.aud, subject, audience, err)
		}
		if _, _, _, _, err := bearerIdentity(r, cfg); err == nil {
			t.Fatal("legacy accepted missing configured application")
		}
	}
}

// Stub PDP tests prove Exposure enforcement, not real Grant authorization.
func TestUserDecisionBinding(t *testing.T) {
	for _, mode := range []string{"allow", "deny", "missing-version", "wrong-version", "null-version", "missing-revision", "stale-revision", "null-revision", "case-alias"} {
		t.Run(mode, func(t *testing.T) {
			upstream := 0
			allow := mode != "deny"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/http-capabilities/decide" {
					upstream++
					_, _ = w.Write([]byte(`{"ok":true}`))
					return
				}
				var in map[string]any
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					t.Error(err)
					return
				}
				if in["wireVersion"] != float64(2) || in["pepPolicyRevision"] != float64(7) || in["providerCredential"].(map[string]any)["audience"] != "resource" {
					t.Error("user request lost version/revision/actual audience")
				}
				recorder := httptest.NewRecorder()
				echoDecisionMap(t, &allow, in, "self", "identity.enroll")(recorder, r)
				var out map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
					t.Error(err)
					return
				}
				out["wireVersion"], out["pepPolicyRevision"] = 2, 7
				switch mode {
				case "missing-version":
					delete(out, "wireVersion")
				case "wrong-version":
					out["wireVersion"] = 1
				case "null-version":
					out["wireVersion"] = nil
				case "missing-revision":
					delete(out, "pepPolicyRevision")
				case "stale-revision":
					out["pepPolicyRevision"] = 8
				case "null-revision":
					out["pepPolicyRevision"] = nil
				case "case-alias":
					delete(out, "wireVersion")
					out["WireVersion"] = 2
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			c := organizationPolicyCatalog(organizationPolicyCapability(""))
			c.AuthorizationMode, c.PepPolicyRevision = "user", 7
			p, err := New(config.ProxyConfig{ProviderID: c.ProviderID, PepClientID: c.PepClientID, CredentialMode: "goauthy", GoauthyIssuer: "https://issuer.example", Origin: server.URL, MaxRequestBytes: 1024, MaxResponseBytes: 1024}, server.URL, server.Client(), 1)
			if err != nil {
				t.Fatal(err)
			}
			p.active = c
			r := httptest.NewRequest("POST", "/accounts/enroll", nil)
			r.Header.Set("Authorization", "Bearer "+goauthyJWT(t, `{"sub":"user","aud":"resource"}`))
			r.Header.Set("X-Organization-ID", "org")
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, r)
			want := 502
			if mode == "allow" {
				want = 200
			}
			if mode == "deny" {
				want = 403
			}
			if w.Code != want || upstream != boolInt(want == 200) {
				t.Fatalf("status=%d upstream=%d", w.Code, upstream)
			}
			if want != 200 && strings.Contains(w.Body.String(), `"ok"`) {
				t.Fatal("business bytes leaked")
			}
		})
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
