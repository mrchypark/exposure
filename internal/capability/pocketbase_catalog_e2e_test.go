package capability

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

// This is a real PocketBase transport test with a controlled PDP, not evidence
// of Grant policy evaluation. It uses only the existing files collection and
// deletes its synthetic record; no schema, hooks, or service APIs are changed.
func TestPocketBaseCatalogNativeTransport(t *testing.T) {
	fixturePath := os.Getenv("PATCH_AUTH_E2E_CONFIG")
	if fixturePath == "" {
		t.Skip("set private fresh PocketBase fixture config")
	}
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ DataOrigin, PrivateDataOrigin, PatchDataOrigin, UpstreamToken string }
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("invalid fixture config")
	}
	origin := f.PrivateDataOrigin
	if origin == "" {
		origin = f.DataOrigin
	}
	if origin == "" {
		origin = f.PatchDataOrigin
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || u.Path != "" || f.UpstreamToken == "" {
		t.Fatal("explicit loopback PocketBase fixture required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	textQuery := func(name string) queryParam { return queryParam{Name: name, Format: "text", MaxBytes: 4096} }
	response := responsePolicy{MaxBytes: 1 << 20, Redirects: "deny", ErrorStatuses: []int{304, 400, 401, 403, 404, 412, 416, 422}, ForwardHeaders: []string{"Accept-Ranges", "Cache-Control", "Content-Disposition", "Content-Length", "Content-Range", "Content-Type", "Etag", "Last-Modified"}}
	collectionResource := &resource{Type: "collection", ID: extractor{Kind: "constant", Value: "files", Format: "asciiToken"}}
	recordResource := &resource{Type: "file", ID: extractor{Kind: "pathSegment", Name: "id", Format: "pocketbaseId"}}
	createAction, readAction := "files.create", "files.read"
	caps := []capability{
		{CapabilityID: "file.create", Version: 1, Enabled: true, AccessMode: "authorized", Method: "POST", PathTemplate: "/api/collections/files/records", ActionID: &createAction, Resource: collectionResource, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "multipart", MaxBytes: 128 << 10, ForwardHeaders: []string{"content-type"}, Authorization: "service-token", ContentTypes: []string{"multipart/form-data"}}, Response: response},
		{CapabilityID: "files.list", Version: 1, Enabled: true, AccessMode: "authorized", Method: "GET", PathTemplate: "/api/collections/files/records", ActionID: &readAction, Resource: collectionResource, Query: queryPolicy{Mode: "exact", Parameters: []queryParam{textQuery("filter"), textQuery("sort"), textQuery("fields"), textQuery("page"), textQuery("perPage"), textQuery("skipTotal")}}, Request: requestPolicy{Body: "none", Authorization: "service-token"}, Response: response},
	}
	for _, method := range []string{"GET", "HEAD"} {
		caps = append(caps, capability{CapabilityID: "file.download." + method, Version: 1, Enabled: true, AccessMode: "authorized", Method: method, PathTemplate: "/api/files/pbc_3446931122/{id}/{filename}", PathParameters: []pathParameter{{Name: "filename", Format: "utf8Segment", MaxBytes: 1024}}, ActionID: &readAction, Resource: recordResource, Query: queryPolicy{Mode: "exact", Parameters: []queryParam{textQuery("download"), textQuery("thumb")}}, Request: requestPolicy{Body: "none", Authorization: "service-token", ForwardHeaders: []string{"If-Modified-Since", "If-Unmodified-Since", "Range"}}, Response: response})
	}
	actions := map[string]string{}
	for i := range caps {
		caps[i].ContractDigest = capabilityDigest(caps[i])
		actions[caps[i].CapabilityID] = *caps[i].ActionID
	}
	catalog := &catalog{SchemaVersion: 1, ProviderID: "files-fixture", PepClientID: "files-pep", Generation: 1, Capabilities: caps, IssuedAt: time.Now().Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	catalog.CatalogDigest = catalogDigest(catalog)
	var decisions atomic.Int64
	var deny atomic.Bool
	var scoped atomic.Bool
	var scopeIDs atomic.Value
	scopeIDs.Store([]string{})
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decisions.Add(1)
		var in map[string]any
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			w.WriteHeader(400)
			return
		}
		credential, ok := in["providerCredential"].(map[string]any)
		if !ok {
			w.WriteHeader(400)
			return
		}
		out := map[string]any{}
		for _, key := range []string{"providerId", "pepClientId", "catalogGeneration", "catalogDigest", "capabilityId", "capabilityVersion", "contractDigest", "resourceType", "resourceId", "method", "canonicalPath", "canonicalQueryDigest", "forwardedHeaderDigest", "bodyDigest", "bodyLength", "providerCredentialDigest", "requestBinding"} {
			out[key] = in[key]
		}
		out["allowed"] = !deny.Load()
		if scoped.Load() {
			out["recordScope"] = map[string]any{"ids": scopeIDs.Load().([]string)}
		}
		out["reason"] = "controlled_transport_fixture"
		out["actionId"] = actions[in["capabilityId"].(string)]
		out["providerSubject"] = credential["subject"]
		out["providerAudience"] = credential["audience"]
		out["principalDigest"] = strings.Repeat("a", 64)
		now := time.Now().Add(-time.Millisecond)
		out["issuedAt"] = now.Format(time.RFC3339Nano)
		out["expiresAt"] = now.Add(time.Second).Format(time.RFC3339Nano)
		json.NewEncoder(w).Encode(out)
	}))
	defer pdp.Close()
	proxy, err := New(config.ProxyConfig{Origin: origin, ProviderID: catalog.ProviderID, PepClientID: catalog.PepClientID, ExpectedCatalogDigest: catalog.CatalogDigest, AuthorizationMode: "service-token", UpstreamToken: f.UpstreamToken, MaxRequestBytes: 128 << 10, MaxResponseBytes: 1 << 20}, pdp.URL, client, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.validateCatalog(catalog); err != nil {
		t.Fatal(err)
	}
	proxy.active = catalog
	front := httptest.NewServer(proxy.Handler())
	defer front.Close()
	token := jwtWithExtraClaims(t)
	request := func(method, target string, body []byte, headers http.Header, service bool) (int, http.Header, []byte) {
		t.Helper()
		r, e := http.NewRequest(method, target, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header = headers.Clone()
		if service {
			r.Header.Set("Authorization", f.UpstreamToken)
		} else {
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("X-Organization-ID", "transport-fixture")
		}
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
		if e != nil {
			t.Fatal(e)
		}
		return res.StatusCode, res.Header, b
	}
	payload := bytes.Repeat([]byte("native PocketBase bytes\n"), 512)
	multipartBody := func(content []byte) ([]byte, string) {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		_ = w.WriteField("name", "Native transport fixture")
		_ = w.WriteField("tags", "catalog-transport")
		part, e := w.CreateFormFile("file", "résumé report.txt")
		if e != nil {
			t.Fatal(e)
		}
		_, _ = part.Write(content)
		_ = w.Close()
		return b.Bytes(), w.FormDataContentType()
	}
	upload, contentType := multipartBody(payload)
	code, _, body := request("POST", front.URL+"/api/collections/files/records", upload, http.Header{"Content-Type": {contentType}}, false)
	if code != 200 {
		t.Fatalf("native multipart create status=%d", code)
	}
	var record struct{ ID, File string }
	if json.Unmarshal(body, &record) != nil || record.ID == "" || record.File == "" {
		t.Fatal("native record/file response missing")
	}
	defer request("DELETE", origin+"/api/collections/files/records/"+record.ID, nil, http.Header{}, true)
	path := "/api/files/pbc_3446931122/" + record.ID + "/" + url.PathEscape(record.File)
	code, headers, body := request("GET", front.URL+path, nil, http.Header{}, false)
	if code != 200 || sha256.Sum256(body) != sha256.Sum256(payload) {
		t.Fatalf("native download bytes/status changed: %d", code)
	}
	nativeCode, nativeHeaders, nativeBody := request("GET", origin+path, nil, http.Header{}, true)
	if nativeCode != code || !bytes.Equal(nativeBody, body) {
		t.Fatal("direct/proxied native response differs")
	}
	for _, name := range []string{"Content-Type", "Content-Disposition", "Last-Modified", "Accept-Ranges"} {
		if headers.Get(name) != nativeHeaders.Get(name) {
			t.Errorf("native %s changed", name)
		}
	}
	code, headers, body = request("GET", front.URL+path, nil, http.Header{"Range": {"bytes=2-19"}}, false)
	if code != 206 || !bytes.Equal(body, payload[2:20]) || headers.Get("Content-Range") == "" {
		t.Fatalf("native range mismatch status=%d", code)
	}
	code, headers, body = request("HEAD", front.URL+path, nil, http.Header{}, false)
	if code != 200 || len(body) != 0 || headers.Get("Content-Length") != nativeHeaders.Get("Content-Length") {
		t.Fatalf("native HEAD mismatch status=%d length=%s", code, headers.Get("Content-Length"))
	}
	if modified := nativeHeaders.Get("Last-Modified"); modified != "" {
		code, _, body = request("GET", front.URL+path, nil, http.Header{"If-Modified-Since": {modified}}, false)
		if code != 304 || len(body) != 0 {
			t.Fatalf("native conditional status=%d", code)
		}
	}
	code, _, _ = request("GET", front.URL+path, nil, http.Header{"Range": {"bytes=999999-"}}, false)
	if code != 416 {
		t.Fatalf("native invalid range status=%d", code)
	}
	code, _, _ = request("GET", front.URL+path, nil, http.Header{"If-Unmodified-Since": {"Sat, 01 Jan 2000 00:00:00 GMT"}}, false)
	if code != 412 {
		t.Fatalf("native failed precondition status=%d", code)
	}
	q := url.Values{"filter": {"id = " + strconv.Quote(record.ID) + " && name ~ 'Native'"}, "sort": {"-created,id"}, "fields": {"id,name,file"}, "perPage": {"1"}, "page": {"1"}}.Encode()
	code, _, body = request("GET", front.URL+"/api/collections/files/records?"+q, nil, http.Header{}, false)
	nativeCode, _, nativeBody = request("GET", origin+"/api/collections/files/records?"+q, nil, http.Header{}, true)
	var proxyJSON, nativeJSON any
	if code != 200 || nativeCode != 200 || json.Unmarshal(body, &proxyJSON) != nil || json.Unmarshal(nativeBody, &nativeJSON) != nil || !reflect.DeepEqual(proxyJSON, nativeJSON) {
		t.Fatalf("native filtered pagination response changed status=%d/%d", code, nativeCode)
	}
	before := decisions.Load()
	code, _, _ = request("GET", front.URL+"/api/collections/files/records?filter=x&filter=y", nil, http.Header{}, false)
	if code != 422 || decisions.Load() != before {
		t.Fatal("duplicate query reached PDP")
	}
	code, _, _ = request("GET", front.URL+"/api/collections/files/records?expand=organization", nil, http.Header{}, false)
	if code != 422 || decisions.Load() != before {
		t.Fatal("unregistered expansion reached PDP")
	}
	tooLarge, largeType := multipartBody(bytes.Repeat([]byte("x"), 128<<10))
	code, _, _ = request("POST", front.URL+"/api/collections/files/records", tooLarge, http.Header{"Content-Type": {largeType}}, false)
	if code != 422 || decisions.Load() != before {
		t.Fatal("oversized multipart reached PDP")
	}
	code, _, _ = request("POST", front.URL+"/api/collections/files/records", upload, http.Header{"Content-Type": {"multipart/form-data"}}, false)
	if code != 422 || decisions.Load() != before {
		t.Fatal("missing multipart boundary reached PDP")
	}
	deny.Store(true)
	code, _, _ = request("GET", front.URL+path, nil, http.Header{}, false)
	if code != 403 {
		t.Fatalf("controlled denied file status=%d", code)
	}
	countRecords := func() int {
		t.Helper()
		status, _, data := request("GET", origin+"/api/collections/files/records?"+url.Values{"filter": {`tags="catalog-transport"`}}.Encode(), nil, http.Header{}, true)
		var list struct{ TotalItems int }
		if status != 200 || json.Unmarshal(data, &list) != nil {
			t.Fatal("native record count failed")
		}
		return list.TotalItems
	}
	beforeDeniedUpload := countRecords()
	code, _, _ = request("POST", front.URL+"/api/collections/files/records", upload, http.Header{"Content-Type": {contentType}}, false)
	if code != 403 || countRecords() != beforeDeniedUpload {
		t.Fatal("denied multipart upload changed PocketBase records")
	}
	// The same unchanged native collection now exercises pre-query row scope.
	// This controlled PDP test proves native pagination/filter semantics only.
	deny.Store(false)
	ids := []string{record.ID}
	for i := 0; i < 2; i++ {
		status, _, data := request("POST", origin+"/api/collections/files/records", upload, http.Header{"Content-Type": {contentType}}, true)
		var extra struct{ ID string }
		if status != 200 || json.Unmarshal(data, &extra) != nil || extra.ID == "" {
			t.Fatal("native scope fixture creation failed")
		}
		ids = append(ids, extra.ID)
		defer request("DELETE", origin+"/api/collections/files/records/"+extra.ID, nil, http.Header{}, true)
	}
	allowedIDs := []string{ids[0], ids[1]}
	sort.Strings(allowedIDs)
	scopeIDs.Store(allowedIDs)
	scoped.Store(true)
	listCap := caps[1]
	listCap.Query.Parameters = []queryParam{textQuery("filter"), textQuery("sort"), {Name: "page", Format: "uint"}, {Name: "perPage", Format: "uint"}, {Name: "skipTotal", Format: "bool"}}
	listCap.RecordScope = &recordScopePolicy{FilterParameter: "filter", RowKey: "id", Grammar: "fexpr", MaxIDs: 100, MaxFilterBytes: 16384, AllowedFields: []string{"created", "file", "id", "name", "tags"}, SortParameter: "sort", Pagination: &paginationPolicy{PageParameter: "page", PageSizeParameter: "perPage", SkipTotalParameter: "skipTotal"}}
	listCap.ContractDigest = capabilityDigest(listCap)
	aliasCap := listCap
	aliasCap.CapabilityID = "files.list.alias"
	aliasCap.PathTemplate = "/api/collections/pbc_3446931122/records"
	aliasCap.ContractDigest = capabilityDigest(aliasCap)
	actions[aliasCap.CapabilityID] = readAction
	scopeCatalog := *catalog
	scopeCatalog.Capabilities = []capability{listCap, aliasCap}
	scopeCatalog.CatalogDigest = catalogDigest(&scopeCatalog)
	scopeProxy, err := New(config.ProxyConfig{Origin: origin, ProviderID: catalog.ProviderID, PepClientID: catalog.PepClientID, ExpectedCatalogDigest: scopeCatalog.CatalogDigest, AuthorizationMode: "service-token", UpstreamToken: f.UpstreamToken, MaxRequestBytes: 128 << 10, MaxResponseBytes: 1 << 20}, pdp.URL, client, 2)
	if err != nil || scopeProxy.validateCatalog(&scopeCatalog) != nil {
		t.Fatal("scope catalog rejected")
	}
	scopeProxy.active = &scopeCatalog
	scopeFront := httptest.NewServer(scopeProxy.Handler())
	defer scopeFront.Close()
	checkPage := func(collection, filter, page string, total int, expectedIDs []string) {
		t.Helper()
		query := url.Values{"filter": {filter}, "page": {page}, "perPage": {"1"}, "sort": {"id"}}.Encode()
		status, _, data := request("GET", scopeFront.URL+"/api/collections/"+collection+"/records?"+query, nil, http.Header{}, false)
		var result struct {
			TotalItems, TotalPages, Page int
			Items                        []struct{ ID string }
		}
		if status != 200 || json.Unmarshal(data, &result) != nil || result.TotalItems != total || result.TotalPages != total {
			t.Fatalf("native scoped pagination mismatch status=%d total=%d pages=%d", status, result.TotalItems, result.TotalPages)
		}
		actual := make([]string, 0, len(result.Items))
		for _, item := range result.Items {
			actual = append(actual, item.ID)
		}
		if !reflect.DeepEqual(actual, expectedIDs) {
			t.Fatal("native scoped page exposed unexpected records")
		}
	}
	clientOR := "id = " + strconv.Quote(ids[2]) + " || tags = \"catalog-transport\""
	checkPage("files", clientOR, "1", 2, allowedIDs[:1])
	checkPage("files", clientOR, "2", 2, allowedIDs[1:])
	checkPage("pbc_3446931122", clientOR, "1", 2, allowedIDs[:1])
	scopeIDs.Store([]string{})
	checkPage("files", clientOR, "1", 0, []string{})
	t.Log("native PocketBase multipart, file hash, Range, HEAD, conditional304, pagination and negative transport verified; PDP controlled, not Grant policy proof")
}
