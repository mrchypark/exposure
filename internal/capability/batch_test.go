package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

func batchTestCatalog() *catalog {
	action := "provider.write"
	request := requestPolicy{Body: "opaque", MaxBytes: 4096, Authorization: "service-token", ContentTypes: []string{"application/json", "multipart/form-data"}, ForwardHeaders: []string{"content-type"}}
	create := capability{CapabilityID: "create", Version: 1, Enabled: true, AccessMode: "authorized", Method: "POST", PathTemplate: "/items", ActionID: &action, Resource: &resource{Type: "collection", ID: extractor{Kind: "constant", Value: "items"}}, Query: queryPolicy{Mode: "none"}, Request: request, Response: responsePolicy{MaxBytes: 4096, Redirects: "deny"}}
	update := create
	update.CapabilityID = "update"
	update.Method = "PATCH"
	update.PathTemplate = "/items/{id}"
	update.Resource = &resource{Type: "item", ID: extractor{Kind: "pathSegment", Name: "id", Format: "asciiToken"}}
	del := update
	del.CapabilityID = "delete"
	del.Method = "DELETE"
	del.Request = requestPolicy{Body: "none", Authorization: "service-token"}
	root := create
	root.CapabilityID = "batch"
	root.PathTemplate = "/batch"
	root.Resource = &resource{Type: "batch", ID: extractor{Kind: "constant", Value: "items"}}
	root.Batch = &batchPolicy{Encoding: "request-array", RequestsPointer: "/requests", MethodField: "method", URLField: "url", BodyField: "body", HeadersField: "headers", MaxOperations: 20, AllowedCapabilityIDs: []string{"create", "delete", "update"}, Upserts: []batchUpsert{{Method: "PUT", PathTemplate: "/items", CreateCapabilityID: "create", UpdateCapabilityID: "update", IDPointer: "/id"}}, Multipart: &batchMultipart{PayloadField: "payload", FileFieldPatterns: []string{"ops.{index}.{field}", "ops[{index}].{field}"}}}
	c := &catalog{SchemaVersion: 1, ProviderID: "provider", PepClientID: "pep", Generation: 1, Capabilities: []capability{create, update, del, root}, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	for i := range c.Capabilities {
		c.Capabilities[i].ContractDigest = capabilityDigest(c.Capabilities[i])
	}
	c.CatalogDigest = catalogDigest(c)
	return c
}
func parseBatchFixture(t *testing.T, c *catalog, data []byte, contentType string) ([]batchChild, error) {
	t.Helper()
	r := httptest.NewRequest("POST", "/batch", bytes.NewReader(data))
	r.Header.Set("Content-Type", contentType)
	root := c.Capabilities[3]
	body, err := readBody(r, root.Request, 4096)
	if err != nil {
		return nil, err
	}
	defer body.close()
	children, err := prepareBatch(c, root, contentType, body)
	forwarded, e := io.ReadAll(body.reader())
	if e != nil || !bytes.Equal(forwarded, data) {
		t.Fatal("batch parser did not restore original spool")
	}
	return children, err
}
func TestBatchParserBindsUpsertAndRejectsAmbiguity(t *testing.T) {
	c := batchTestCatalog()
	if err := validateBatchCatalog(c); err != nil {
		t.Fatal(err)
	}
	children, err := parseBatchFixture(t, c, []byte(`{"requests":[{"method":"PUT","url":"/items","body":{"id":"record1","value":9007199254740993}}]}`), "application/json")
	if err != nil || len(children) != 2 || children[0].CapabilityID != "create" || children[1].CapabilityID != "update" || children[0].UpsertID != "record1" || children[1].ResourceID != "record1" || children[0].BodyDigest != children[1].BodyDigest {
		t.Fatalf("upsert proof %#v %v", children, err)
	}
	digest := batchChildrenDigest(children)
	children[1].ResourceID = "other"
	if batchChildrenDigest(children) == digest {
		t.Fatal("batch child mutation did not change digest")
	}
	for _, bad := range []string{`{"requests":[],"requests":[{"method":"POST","url":"/items"}]}`, `{"requests":[{"method":"POST","method":"DELETE","url":"/items"}]}`, `{"requests":[{"method":"PUT","url":"/items","body":{"id":1}}]}`, `{"requests":[{"method":"GET","url":"/items"}]}`, `{"requests":[{"method":"POST","url":"//example.test/items"}]}`, `{"requests":[{"method":"POST","url":"/a/../items"}]}`, `{"requests":[{"method":"POST","url":"/items?expand=owner"}]}`, `{"requests":[{"method":"POST","url":"/batch"}]}`, `{"requests":[{"method":"POST","url":"/items","headers":{"Authorization":"x"}}]}`, `{"requests":[{"method":"DELETE","url":"/items/id","body":{"id":"other"}}]}`, `{"requests":[]}`} {
		if _, err := parseBatchFixture(t, c, []byte(bad), "application/json"); err == nil {
			t.Errorf("accepted ambiguous batch %s", bad)
		}
	}
}
func TestBatchMultipartRejectsConflictingIndexAndFields(t *testing.T) {
	c := batchTestCatalog()
	cases := []struct {
		name, payload    string
		fields           []string
		duplicatePayload bool
		want             bool
	}{
		{name: "dot", payload: `{"requests":[{"method":"POST","url":"/items","body":{}}]}`, fields: []string{"ops.0.file"}, want: true},
		{name: "bracket", payload: `{"requests":[{"method":"POST","url":"/items","body":{}}]}`, fields: []string{"ops[0].file"}, want: true},
		{name: "two aliases", payload: `{"requests":[{"method":"POST","url":"/items"}]}`, fields: []string{"ops.0.file", "ops[0].file"}},
		{name: "out of bounds", payload: `{"requests":[{"method":"POST","url":"/items"}]}`, fields: []string{"ops.1.file"}},
		{name: "reserved id", payload: `{"requests":[{"method":"PUT","url":"/items"}]}`, fields: []string{"ops.0.id"}},
		{name: "collision", payload: `{"requests":[{"method":"POST","url":"/items","body":{"file":"value"}}]}`, fields: []string{"ops.0.file"}},
		{name: "duplicate payload", payload: `{"requests":[{"method":"POST","url":"/items"}]}`, duplicatePayload: true},
		{name: "duplicate json key", payload: `{"requests":[{"method":"POST","url":"/items","body":{"id":"x","id":"y"}}]}`},
		{name: "delete attachment", payload: `{"requests":[{"method":"DELETE","url":"/items/id"}]}`, fields: []string{"ops.0.file"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			w := multipart.NewWriter(&data)
			_ = w.WriteField("payload", tc.payload)
			if tc.duplicatePayload {
				_ = w.WriteField("payload", tc.payload)
			}
			for _, field := range tc.fields {
				part, e := w.CreateFormFile(field, "fixture.txt")
				if e != nil {
					t.Fatal(e)
				}
				_, _ = part.Write([]byte("file bytes"))
			}
			_ = w.Close()
			_, err := parseBatchFixture(t, c, data.Bytes(), w.FormDataContentType())
			if (err == nil) != tc.want {
				t.Fatalf("multipart accepted=%v want%v", err == nil, tc.want)
			}
			if tc.want {
				restricted := batchTestCatalog()
				restricted.Capabilities[0].Request.ContentTypes = []string{"application/json"}
				if _, err := parseBatchFixture(t, restricted, data.Bytes(), w.FormDataContentType()); err == nil {
					t.Fatal("multipart escaped JSON-only child policy")
				}
			}
		})
	}
}
func TestBatchDecisionBindingAndExpiryBeforeDispatch(t *testing.T) {
	c := batchTestCatalog()
	var decisions, upstream atomic.Int64
	var tamper atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/http-capabilities/decide" {
			upstream.Add(1)
			w.WriteHeader(200)
			return
		}
		decisions.Add(1)
		var in map[string]any
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			t.Error("decision input")
			return
		}
		credential := in["providerCredential"].(map[string]any)
		out := map[string]any{}
		for _, key := range []string{"providerId", "pepClientId", "catalogGeneration", "catalogDigest", "capabilityId", "capabilityVersion", "contractDigest", "resourceType", "resourceId", "method", "canonicalPath", "canonicalQueryDigest", "forwardedHeaderDigest", "bodyDigest", "bodyLength", "providerCredentialDigest", "requestBinding", "batchDigest"} {
			out[key] = in[key]
		}
		out["allowed"] = true
		out["reason"] = "test"
		out["actionId"] = "provider.write"
		out["providerSubject"] = credential["subject"]
		out["providerAudience"] = credential["audience"]
		out["principalDigest"] = strings.Repeat("a", 64)
		now := time.Now().Add(-time.Millisecond)
		out["issuedAt"] = now.Format(time.RFC3339Nano)
		out["expiresAt"] = now.Add(time.Second).Format(time.RFC3339Nano)
		if tamper.Load() {
			out["batchDigest"] = "sha256:" + strings.Repeat("f", 64)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	p, err := New(config.ProxyConfig{ProviderID: "provider", PepClientID: "pep", Origin: server.URL, ExpectedCatalogDigest: c.CatalogDigest, AuthorizationMode: "service-token", UpstreamToken: "test-service", MaxRequestBytes: 4096, MaxResponseBytes: 4096}, server.URL, server.Client(), 2)
	if err != nil {
		t.Fatal(err)
	}
	p.active = c
	send := func(want int) {
		r := httptest.NewRequest("POST", "/batch", strings.NewReader(`{"requests":[{"method":"POST","url":"/items","body":{}}]}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
		r.Header.Set("X-Organization-ID", "org")
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("batch status%d want%d %s", w.Code, want, w.Body.String())
		}
	}
	send(200)
	tamper.Store(true)
	send(502)
	if decisions.Load() != 2 || upstream.Load() != 1 {
		t.Fatalf("decisions%d upstream%d", decisions.Load(), upstream.Load())
	}
	r := httptest.NewRequest("POST", "/batch", nil).WithContext(context.WithValue(context.Background(), authorizationExpiryKey{}, time.Now().Add(-time.Second)))
	w := httptest.NewRecorder()
	p.forward(w, r, c.Capabilities[3], "", http.Header{}, nil)
	if w.Code != 502 || upstream.Load() != 1 {
		t.Fatal("expired decision reached upstream")
	}
}

func TestBatchUpsertIgnoresDisabledHistoricalVersions(t *testing.T) {
	c := batchTestCatalog()
	for _, index := range []int{0, 1} {
		old := c.Capabilities[index]
		old.Enabled = false
		old.Version = 99
		old.ContractDigest = capabilityDigest(old)
		c.Capabilities = append(c.Capabilities, old)
	}
	if err := validateBatchCatalog(c); err != nil {
		t.Fatal(err)
	}
	children, err := parseBatchFixture(t, c, []byte(`{"requests":[{"method":"PUT","url":"/items","body":{"id":"record1"}}]}`), "application/json")
	if err != nil || len(children) != 2 || children[0].CapabilityVersion != 1 || children[1].CapabilityVersion != 1 {
		t.Fatalf("historical versions shadowed current upsert: %#v %v", children, err)
	}
	c.Capabilities[4].Enabled = true
	if err := validateBatchCatalog(c); err == nil {
		t.Fatal("ambiguous active reference accepted")
	}
}
