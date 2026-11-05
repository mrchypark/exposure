package capability

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

func responseTestCatalog() *catalog {
	action := "provider.root.read"
	c := &catalog{SchemaVersion: 1, ProviderID: "provider", PepClientID: "pep", Generation: 1, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano), ResponseResources: []responseResource{
		{Key: "child", ActionID: "provider.child.read", ResourceType: "child", IDField: "id", IDFormat: "asciiToken", IdentityField: "kind", IdentityValue: "child", Relations: []responseRelation{{Field: "next", TargetKey: "child"}}},
		{Key: "root", ActionID: action, ResourceType: "root", IDField: "id", IDFormat: "asciiToken", IdentityField: "kind", IdentityValue: "root", Relations: []responseRelation{{Field: "children", TargetKey: "child"}}},
	}, Capabilities: []capability{{CapabilityID: "root.read", Version: 1, Enabled: true, AccessMode: "authorized", Method: "GET", PathTemplate: "/items/{id}", ActionID: &action, Resource: &resource{Type: "root", ID: extractor{Kind: "pathSegment", Name: "id", Format: "asciiToken"}}, Query: queryPolicy{Mode: "exact", Parameters: []queryParam{{Name: "include", Format: "text", MaxBytes: 4096}}}, Request: requestPolicy{Body: "none", Authorization: "service-token"}, Response: responsePolicy{MaxBytes: 8192, Redirects: "deny", ErrorStatuses: []int{404}, ForwardHeaders: []string{"content-type", "x-record"}}, ResponseAuthorization: &responseAuthorizationPolicy{RootKey: "root", ExpansionField: "expanded", QueryParameter: "include", MaxDepth: 6, MaxRecords: 200}}}}
	c.Capabilities[0].ContractDigest = capabilityDigest(c.Capabilities[0])
	c.CatalogDigest = catalogDigest(c)
	return c
}
func TestExpandedResponseGraphRejectsMismatchedOrUnrequestedRecords(t *testing.T) {
	c := responseTestCatalog()
	if err := validateResponseAuthorization(c); err != nil {
		t.Fatal(err)
	}
	cap := c.Capabilities[0]
	tree, err := requestedExpansion("include=children", c, cap)
	if err != nil {
		t.Fatal(err)
	}
	good := `{"id":"r1","kind":"root","children":["c1","c2"],"expanded":{"children":[{"id":"c1","kind":"child"},{"id":"c2","kind":"child"}]}}`
	refs, err := collectResponseReferences(c, cap, tree, []byte(good), "r1")
	if err != nil || len(refs) != 3 || refs[1].ParentIndex == nil || *refs[1].ParentIndex != 0 || refs[2].RelationField != "children" {
		t.Fatalf("references %#v %v", refs, err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"id":"c1"`, `"id":"c3"`, 1), strings.Replace(good, `"kind":"child"`, `"kind":"root"`, 1), strings.Replace(good, `"id":"r1"`, `"id":"other"`, 1), strings.Replace(good, `"kind":"root"`, `"id":"r2","kind":"root"`, 1),
		`{"id":"r1","kind":"root","children":"c1","expanded":{"children":{"id":"c1","kind":"child","next":"c2","expanded":{"next":{"id":"c2","kind":"child"}}}}}`,
		`{"id":"r1","kind":"root","expanded":{"unknown":null}}`,
	} {
		if _, err := collectResponseReferences(c, cap, tree, []byte(bad), "r1"); err == nil {
			t.Errorf("accepted malformed expansion %s", bad)
		}
	}
	policy := *cap.ResponseAuthorization
	policy.MaxRecords = 2
	cap.ResponseAuthorization = &policy
	if _, err := collectResponseReferences(c, cap, tree, []byte(good), "r1"); err == nil {
		t.Fatal("record bound ignored")
	}
	for _, raw := range []string{"include=unknown", "include=children,children", "include=children.next.next.next.next.next.next", "include=children&include=children", "include="} {
		if _, err := requestedExpansion(raw, c, c.Capabilities[0]); err == nil {
			t.Errorf("accepted query %s", raw)
		}
	}
	empty := c.Capabilities[0]
	policy = *empty.ResponseAuthorization
	policy.RecordsPointer = "/items"
	empty.ResponseAuthorization = &policy
	refs, err = collectResponseReferences(c, empty, tree, []byte(`{"items":[],"totalItems":0}`), "items")
	if err != nil || len(refs) != 0 || responseReferencesDigest(refs) != responseReferencesDigest(nil) {
		t.Fatal("empty page reference semantics")
	}
}
func TestExpandedResponseIsWithheldUntilBoundRecheck(t *testing.T) {
	c := responseTestCatalog()
	var mode, decisions, upstreams atomic.Int64
	var nonce atomic.Value
	native := `{"id":"r1","kind":"root","children":"c1","expanded":{"children":{"id":"c1","kind":"child"}}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/http-capabilities/decide" {
			upstreams.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Record", "private-native-metadata")
			_, _ = w.Write([]byte(native))
			return
		}
		decisions.Add(1)
		var in map[string]any
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			t.Error("invalid decision input")
			return
		}
		for _, field := range []string{"wireVersion", "pepPolicyRevision"} {
			if _, present := in[field]; present {
				t.Errorf("legacy request contains unsupported field %s", field)
			}
		}
		_, post := in["responseDigest"]
		if !post {
			nonce.Store(in["requestBinding"])
		} else if nonce.Load() != in["requestBinding"] {
			t.Error("response check changed original request binding")
		}
		cred := in["providerCredential"].(map[string]any)
		out := map[string]any{}
		for _, key := range []string{"providerId", "pepClientId", "catalogGeneration", "catalogDigest", "capabilityId", "capabilityVersion", "contractDigest", "resourceType", "resourceId", "method", "canonicalPath", "canonicalQueryDigest", "forwardedHeaderDigest", "bodyDigest", "bodyLength", "providerCredentialDigest", "requestBinding", "responseDigest", "responseLength", "responseReferencesDigest"} {
			if v, ok := in[key]; ok {
				out[key] = v
			}
		}
		out["allowed"] = !post || mode.Load() != 1
		out["reason"] = "test"
		out["actionId"] = "provider.root.read"
		out["providerSubject"] = cred["subject"]
		out["providerAudience"] = cred["audience"]
		out["principalDigest"] = strings.Repeat("a", 64)
		now := time.Now().Add(-time.Millisecond)
		out["issuedAt"] = now.Format(time.RFC3339Nano)
		out["expiresAt"] = now.Add(time.Second).Format(time.RFC3339Nano)
		if post && mode.Load() == 2 {
			out["responseDigest"] = "sha256:" + strings.Repeat("f", 64)
		}
		if post && mode.Load() == 3 {
			out["expiresAt"] = now.Add(-time.Second).Format(time.RFC3339Nano)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	p, err := New(config.ProxyConfig{ProviderID: "provider", PepClientID: "pep", Origin: server.URL, ExpectedCatalogDigest: c.CatalogDigest, AuthorizationMode: "service-token", UpstreamToken: "test-service", MaxRequestBytes: 8192, MaxResponseBytes: 8192}, server.URL, server.Client(), 2)
	if err != nil {
		t.Fatal(err)
	}
	p.active = c
	for i, want := range []int{200, 403, 502, 502} {
		mode.Store(int64(i))
		r := httptest.NewRequest("GET", "/items/r1?include=children", nil)
		r.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
		r.Header.Set("X-Organization-ID", "org")
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("response status%d want%d %s", w.Code, want, w.Body.String())
		}
		if want == 200 {
			if w.Body.String() != native {
				t.Fatal("authorized bytes changed")
			}
		} else if strings.Contains(w.Body.String(), "c1") || w.Header().Get("X-Record") != "" {
			t.Fatal("response bytes or metadata leaked before recheck")
		}
	}
	if decisions.Load() != 8 || upstreams.Load() != 4 {
		t.Fatalf("decision/fetch counts%d/%d", decisions.Load(), upstreams.Load())
	}
}

func TestUserExpandedResponsePinsPrincipalAndRevision(t *testing.T) {
	for _, mode := range []string{"allow", "principal-change", "revision-change"} {
		t.Run(mode, func(t *testing.T) {
			c := responseTestCatalog()
			c.AuthorizationMode, c.PepPolicyRevision = "user", 7
			var decisions, upstreams atomic.Int64
			var nonce atomic.Value
			native := `{"id":"r1","kind":"root","children":"c1","expanded":{"children":{"id":"c1","kind":"child"}}}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/http-capabilities/decide" {
					upstreams.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Record", "private-native-metadata")
					_, _ = w.Write([]byte(native))
					return
				}
				decisions.Add(1)
				var in map[string]any
				if json.NewDecoder(r.Body).Decode(&in) != nil {
					t.Error("invalid user decision input")
					return
				}
				if in["wireVersion"] != float64(2) || in["pepPolicyRevision"] != float64(7) {
					t.Error("user decision changed original version/revision")
				}
				_, post := in["responseDigest"]
				if !post {
					nonce.Store(in["requestBinding"])
				} else if nonce.Load() != in["requestBinding"] {
					t.Error("response decision changed original binding")
				}
				allow := true
				recorder := httptest.NewRecorder()
				echoDecisionMap(t, &allow, in, "r1", "provider.root.read")(recorder, r)
				var out map[string]any
				if json.Unmarshal(recorder.Body.Bytes(), &out) != nil {
					t.Error("invalid test decision")
					return
				}
				for _, key := range []string{"wireVersion", "pepPolicyRevision", "responseDigest", "responseLength", "responseReferencesDigest"} {
					if value, present := in[key]; present {
						out[key] = value
					}
				}
				if post && mode == "principal-change" {
					out["principalDigest"] = strings.Repeat("b", 64)
				}
				if post && mode == "revision-change" {
					out["pepPolicyRevision"] = 8
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			p, err := New(config.ProxyConfig{ProviderID: "provider", PepClientID: "pep", Origin: server.URL, ExpectedCatalogDigest: c.CatalogDigest, AuthorizationMode: "service-token", UpstreamToken: "test-service", CredentialMode: "goauthy", GoauthyIssuer: "https://issuer.example", MaxRequestBytes: 8192, MaxResponseBytes: 8192}, server.URL, server.Client(), 2)
			if err != nil {
				t.Fatal(err)
			}
			p.active = c
			r := httptest.NewRequest("GET", "/items/r1?include=children", nil)
			r.Header.Set("Authorization", "Bearer "+goauthyJWT(t, `{"sub":"user","aud":"resource"}`))
			r.Header.Set("X-Organization-ID", "org")
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, r)
			if decisions.Load() != 2 || upstreams.Load() != 1 {
				t.Fatalf("decisions/upstreams=%d/%d", decisions.Load(), upstreams.Load())
			}
			if mode == "allow" {
				if w.Code != 200 || w.Body.String() != native {
					t.Fatalf("control status=%d body=%s", w.Code, w.Body.String())
				}
			} else if w.Code != 502 || strings.Contains(w.Body.String(), "r1") || strings.Contains(w.Body.String(), "c1") || w.Header().Get("X-Record") != "" {
				t.Fatalf("post-read mismatch leaked data: status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
