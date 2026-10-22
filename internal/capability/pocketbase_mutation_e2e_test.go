package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

// The wrapper runs this separately after the read-only generated catalog.
// Whole-record writes intentionally include native relation fields and hooks.
func TestPocketBaseMutations(t *testing.T) {
	if os.Getenv("PATCH_AUTH_E2E_CONFIG") == "" || os.Getenv("PATCH_DATA_NATIVE_CATALOG") == "" {
		t.Skip("set fresh local generated-catalog fixture")
	}
	var f struct{ AuthOrigin, CollectionID, AllowIdentity, AllowPassword, DataOrigin, VoterURL, GrantURL, GrantMasterKeyFile, GrantAppKey, ProviderID, PEPClientID, ApplicationID, OrganizationID, UpstreamToken string }
	raw, err := os.ReadFile(os.Getenv("PATCH_AUTH_E2E_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{f.AuthOrigin, f.DataOrigin, f.VoterURL, f.GrantURL} {
		u, e := url.Parse(origin)
		if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
			t.Fatal("loopback fixture required")
		}
	}
	master, err := os.ReadFile(f.GrantMasterKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	token := ""
	request := func(method, target string, v any, service bool) (int, []byte) {
		t.Helper()
		var b []byte
		if v != nil {
			var e error
			b, e = json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
		}
		r, e := http.NewRequest(method, target, bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Organization-ID", f.OrganizationID)
		r.Header.Set("Authorization", "Bearer "+token)
		if service {
			r.Header.Set("Authorization", f.UpstreamToken)
		}
		if strings.HasPrefix(target, f.VoterURL+"/") || strings.HasPrefix(target, f.GrantURL+"/") {
			r.Header.Set("X-Grant-Master-Key", strings.TrimSpace(string(master)))
			r.Header.Set("X-Grant-App-Auth-Key", f.GrantAppKey)
			addGrantActionPrecondition(t, client, r)
		}
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, e = io.ReadAll(io.LimitReader(res.Body, 4<<20))
		if e != nil {
			t.Fatal(e)
		}
		return res.StatusCode, b
	}
	must := func(method, target string, v any) []byte {
		t.Helper()
		code, b := request(method, target, v, false)
		if code < 200 || code >= 300 {
			t.Fatalf("%s %s status %d: %s", method, target, code, b)
		}
		return b
	}
	var login struct{ Token string }
	if json.Unmarshal(must("POST", f.AuthOrigin+"/api/collections/users/auth-with-password", map[string]string{"identity": f.AllowIdentity, "password": f.AllowPassword}), &login) != nil || login.Token == "" {
		t.Fatal("login")
	}
	token = login.Token
	var owner struct{ UserID string }
	if json.Unmarshal(must("POST", f.VoterURL+"/api/v1/admin/bootstrap/owner", map[string]string{"organizationId": f.OrganizationID}), &owner) != nil || owner.UserID == "" {
		t.Fatal("owner")
	}
	var previous catalog
	if json.Unmarshal(must("GET", f.GrantURL+"/api/v2/http-capabilities/catalog/"+f.ProviderID+"?pepClientId="+f.PEPClientID, nil), &previous) != nil || previous.Generation == 0 {
		t.Fatal("previous catalog")
	}
	raw, err = os.ReadFile(os.Getenv("PATCH_DATA_NATIVE_CATALOG"))
	if err != nil {
		t.Fatal(err)
	}
	var generated catalog
	if err = json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	generated.ProviderID = f.ProviderID
	generated.Generation = previous.Generation + 1
	generated.CatalogDigest = catalogDigest(&generated)
	var actions []map[string]any
	raw, err = os.ReadFile(os.Getenv("PATCH_DATA_NATIVE_ACTIONS"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &actions); err != nil {
		t.Fatal(err)
	}
	actionIDs := []string{}
	lists := map[string][]capability{}
	for _, c := range generated.Capabilities {
		if c.RecordScope != nil {
			lists[c.Resource.Type] = append(lists[c.Resource.Type], c)
		}
		if c.ActionID != nil && !slices.Contains(actionIDs, *c.ActionID) {
			actionIDs = append(actionIDs, *c.ActionID)
		}
	}
	if len(lists) != 42 {
		t.Fatalf("generated collections %d, want 42", len(lists))
	}
	must("PUT", f.VoterURL+"/api/v1/admin/providers/"+f.ProviderID+"/actions", map[string]any{"actions": actions})
	app := f.VoterURL + "/api/v1/admin/orgs/" + f.OrganizationID + "/apps/" + f.ApplicationID + "/trust"
	must("PUT", app, map[string]bool{"trusted": false})
	must("PUT", f.VoterURL+"/api/v1/orgs/"+f.OrganizationID+"/apps/"+f.ApplicationID+"/actions", map[string]any{"actionIds": actionIDs})
	must("PUT", app, map[string]bool{"trusted": true})
	org := f.VoterURL + "/api/v1/orgs/" + f.OrganizationID
	must("POST", org+"/roles", map[string]string{"id": "mutation-operator", "code": "mutation-operator", "name": "Explicit native mutation"})
	must("PUT", org+"/roles/mutation-operator/actions", map[string]any{"actionIds": actionIDs})
	must("POST", f.VoterURL+"/api/v1/admin/providers/"+f.ProviderID+"/http-capability-generations", map[string]any{"schemaVersion": 1, "generation": generated.Generation, "expectedLatestGeneration": previous.Generation, "capabilities": generated.Capabilities, "responseResources": generated.ResponseResources, "catalogDigest": generated.CatalogDigest})
	must("POST", f.VoterURL+"/api/v1/admin/providers/"+f.ProviderID+"/http-capability-active", map[string]any{"expectedGeneration": previous.Generation, "expectedCatalogDigest": previous.CatalogDigest, "targetGeneration": generated.Generation, "targetCatalogDigest": generated.CatalogDigest})
	capture := &mutationCaptureTransport{base: tr, origin: f.DataOrigin}
	proxyClient := &http.Client{Transport: capture, Timeout: 5 * time.Second}
	proxy, err := New(config.ProxyConfig{CredentialMode: "pocketbase", PocketBaseIssuer: f.AuthOrigin, PocketBaseCollectionID: f.CollectionID, PocketBaseApplicationID: f.ApplicationID, ProviderID: f.ProviderID, PepClientID: f.PEPClientID, Origin: f.DataOrigin, ExpectedCatalogDigest: generated.CatalogDigest, AppAuthKey: f.GrantAppKey, AuthorizationMode: "service-token", UpstreamToken: f.UpstreamToken, MaxRequestBytes: 128 << 20, MaxResponseBytes: 128 << 20}, f.GrantURL, proxyClient, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(proxy.Handler())
	defer front.Close()
	bind := func(name, kind, id, role string) {
		t.Helper()
		must("POST", org+"/bindings", map[string]any{"id": name, "subjectType": "user", "subjectId": owner.UserID, "subjectOrganizationId": f.OrganizationID, "providerId": f.ProviderID, "resourceType": kind, "resourceId": id, "roleId": role, "agreementId": nil, "state": "active"})
	}
	revoke := func(name string) { t.Helper(); must("DELETE", org+"/bindings/"+name, nil) }
	rawRequest := func(method, path string, b []byte, headers http.Header, want int) []byte {
		t.Helper()
		r, e := http.NewRequest(method, front.URL+path, bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		r.Header = headers.Clone()
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Organization-ID", f.OrganizationID)
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		out, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
		if e != nil {
			t.Fatal(e)
		}
		if res.StatusCode != want {
			if path == "/api/batch" || strings.Contains(path, "expand=") {
				capture.mu.Lock()
				t.Logf("last Grant batch result: %s", capture.decisionReason)
				capture.mu.Unlock()
			}
			t.Fatalf("%s %s status%d want%d: %s", method, path, res.StatusCode, want, out)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("authorized response may be reused without a new Grant decision")
		}
		if strings.HasSuffix(path, "?download=1") && !strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment;") {
			t.Fatal("native download=1 disposition changed")
		}
		return out
	}
	jsonHeaders := http.Header{"Content-Type": {"application/json"}}
	// Every generated write/file route denies before reaching unchanged PocketBase.
	mutations, downloads := 0, 0
	for _, c := range generated.Capabilities {
		if c.Batch != nil {
			continue
		}
		if c.Method == "POST" || c.Method == "PATCH" || c.Method == "DELETE" {
			mutations++
			path := strings.ReplaceAll(c.PathTemplate, "{id}", "mutation000001a")
			body := []byte(`{}`)
			headers := jsonHeaders
			if c.Method == "DELETE" {
				body = nil
				headers = http.Header{}
			}
			rawRequest(c.Method, path, body, headers, 403)
		}
		if strings.HasPrefix(c.PathTemplate, "/api/files/") {
			downloads++
			path := strings.ReplaceAll(strings.ReplaceAll(c.PathTemplate, "{id}", "mutation000001a"), "{filename}", "fixture.txt")
			rawRequest(c.Method, path, nil, http.Header{}, 403)
		}
	}
	if mutations != 180 || downloads != 20 {
		t.Fatalf("generated mutation/file counts %d/%d", mutations, downloads)
	}
	capture.mu.Lock()
	initialUpstreamCalls := capture.calls
	capture.mu.Unlock()
	if initialUpstreamCalls != 0 {
		t.Fatal("unbound generated routes reached native upstream")
	}
	for _, name := range []string{"plants_viewer", "panelmaps_viewer", "temporary_panelmaps", "temporary_plants", "temporary_blueprints", "blueprints_viewer", "latest_loss_reports", "reports_v2_list", "blueprints_list", "temporary_blueprints_list", "blueprints_viewer_list", "rsd_command_tasks"} {
		for _, method := range []string{"POST", "PATCH", "DELETE"} {
			path := "/api/collections/" + name + "/records"
			if method != "POST" {
				path += "/mutation000001a"
			}
			rawRequest(method, path, nil, http.Header{}, 404)
		}
	}
	// Same authority tuple through both native aliases; record grants cannot create.
	if code, body := request("POST", f.DataOrigin+"/api/collections/plants/records", map[string]any{"id": "mutationplant1a", "name": "Mutation relation target", "organization": "fixtureorg0001a", "permission": "fixtureperm001a"}, true); code != 200 {
		t.Fatalf("seed mutation plant %d: %s", code, body)
	}
	defer request("DELETE", f.DataOrigin+"/api/collections/plants/records/mutationplant1a", nil, true)
	ids := []string{"mutation000001a", "mutation000002a"}
	permissionPaths := []string{"/api/collections/panelmaps/records", "/api/collections/l17r68r7ddzqcij/records"}
	bind("mutation-wrong-create", "panelmaps", ids[0], "mutation-operator")
	for _, path := range permissionPaths {
		rawRequest("POST", path, []byte(`{"id":"mutation000001a"}`), jsonHeaders, 403)
	}
	revoke("mutation-wrong-create")
	bind("mutation-create-panelmaps", "collection", "panelmaps", "mutation-operator")
	for i, path := range permissionPaths {
		body := []byte("{ \n  \"id\" : " + strconv.Quote(ids[i]) + " , \"data\": {\"fixture\":true}, \"plant\" : \"fixtureplant01a\"\n}\n")
		rawRequest("POST", path, body, jsonHeaders, 200)
		capture.check(t, body, "application/json")
		defer request("DELETE", f.DataOrigin+permissionPaths[0]+"/"+ids[i], nil, true)
	}
	revoke("mutation-create-panelmaps")
	for _, path := range permissionPaths {
		rawRequest("POST", path, []byte(`{}`), jsonHeaders, 403)
	}
	bind("mutation-exact-permission", "panelmaps", ids[0], "mutation-operator")
	update := []byte("{\n \"plant\" : \"mutationplant1a\", \"data\" : {\"updated\":true}\n}\n")
	for _, path := range permissionPaths {
		rawRequest("PATCH", path+"/"+ids[0], update, jsonHeaders, 200)
		capture.check(t, update, "application/json")
		rawRequest("PATCH", path+"/"+ids[1], update, jsonHeaders, 403)
		rawRequest("DELETE", path+"/"+ids[1], nil, http.Header{}, 403)
	}
	revoke("mutation-exact-permission")
	rawRequest("PATCH", permissionPaths[0]+"/"+ids[0], update, jsonHeaders, 403)
	rawRequest("DELETE", permissionPaths[0]+"/"+ids[0], nil, http.Header{}, 403)
	// Native state confirms denied updates/deletes did not remove or alter target.
	code, b := request("GET", f.DataOrigin+permissionPaths[0]+"/"+ids[1], nil, true)
	var untouched struct{ Plant string }
	if code != 200 || json.Unmarshal(b, &untouched) != nil || untouched.Plant != "fixtureplant01a" {
		t.Fatal("denied mutation changed native record")
	}
	for i, path := range permissionPaths {
		name := fmt.Sprintf("mutation-delete-%d", i)
		bind(name, "panelmaps", ids[i], "mutation-operator")
		rawRequest("DELETE", path+"/"+ids[i], nil, http.Header{}, 204)
		revoke(name)
	}
	// File CRUD remains native multipart; separate file authority gates downloads.
	filePaths := []string{"/api/collections/files/records", "/api/collections/pbc_3446931122/records"}
	multipartBody := func(payload []byte) ([]byte, http.Header) {
		t.Helper()
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		if e := w.WriteField("name", "Native mutation fixture"); e != nil {
			t.Fatal(e)
		}
		part, e := w.CreateFormFile("file", "résumé fixture.txt")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = part.Write(payload); e != nil {
			t.Fatal(e)
		}
		if e = w.Close(); e != nil {
			t.Fatal(e)
		}
		return b.Bytes(), http.Header{"Content-Type": {w.FormDataContentType()}}
	}
	payload := []byte("whole-record authorized file contents\n")
	upload, uploadHeaders := multipartBody(payload)
	for _, path := range filePaths {
		rawRequest("POST", path, upload, uploadHeaders, 403)
	}
	bind("mutation-create-files", "collection", "files", "mutation-operator")
	var file struct{ ID, File string }
	if json.Unmarshal(rawRequest("POST", filePaths[0], upload, uploadHeaders, 200), &file) != nil || file.ID == "" {
		t.Fatal("file create response")
	}
	capture.check(t, upload, uploadHeaders.Get("Content-Type"))
	defer request("DELETE", f.DataOrigin+filePaths[0]+"/"+file.ID, nil, true)
	revoke("mutation-create-files")
	must("POST", org+"/roles", map[string]string{"id": "mutation-read-only", "code": "mutation-read-only", "name": "Record read only"})
	must("PUT", org+"/roles/mutation-read-only/actions", map[string]any{"actionIds": []string{"patch-data.files.read"}})
	bind("mutation-file-read-only", "files", file.ID, "mutation-read-only")
	downloadPaths := []string{"/api/files/files/" + file.ID + "/" + url.PathEscape(file.File), "/api/files/pbc_3446931122/" + file.ID + "/" + url.PathEscape(file.File)}
	for _, path := range downloadPaths {
		rawRequest("GET", path, nil, http.Header{}, 403)
		rawRequest("HEAD", path, nil, http.Header{}, 403)
	}
	revoke("mutation-file-read-only")
	bind("mutation-file-record", "files", file.ID, "mutation-operator")
	for _, path := range downloadPaths {
		if got := rawRequest("GET", path, nil, http.Header{}, 200); !bytes.Equal(got, payload) {
			t.Fatal("file bytes changed")
		}
		if got := rawRequest("HEAD", path, nil, http.Header{}, 200); len(got) != 0 {
			t.Fatal("HEAD body")
		}
		if got := rawRequest("GET", path, nil, http.Header{"Range": {"bytes=2-9"}}, 206); !bytes.Equal(got, payload[2:10]) {
			t.Fatal("range bytes changed")
		}
		for _, value := range []string{"1", "0", "TRUE", "FALSE"} {
			if got := rawRequest("GET", path+"?download="+value, nil, http.Header{}, 200); !bytes.Equal(got, payload) {
				t.Fatal("native download query changed bytes")
			}
		}
		rawRequest("GET", path, nil, http.Header{"If-Match": {`"not-the-native-etag"`}}, 412)
	}
	replacement := []byte("updated native multipart bytes\n")
	patch, patchHeaders := multipartBody(replacement)
	if json.Unmarshal(rawRequest("PATCH", filePaths[1]+"/"+file.ID, patch, patchHeaders, 200), &file) != nil {
		t.Fatal("multipart update")
	}
	capture.check(t, patch, patchHeaders.Get("Content-Type"))
	latestDownload := "/api/files/files/" + file.ID + "/" + url.PathEscape(file.File)
	if got := rawRequest("GET", latestDownload, nil, http.Header{}, 200); !bytes.Equal(got, replacement) {
		t.Fatal("updated bytes changed")
	}
	revoke("mutation-file-record")
	rawRequest("PATCH", filePaths[0]+"/"+file.ID, patch, patchHeaders, 403)
	rawRequest("DELETE", filePaths[0]+"/"+file.ID, nil, http.Header{}, 403)
	rawRequest("GET", latestDownload, nil, http.Header{}, 403)
	// Generated map records have native 62-character IDs, unlike ordinary PB IDs.
	bind("mutation-create-org", "collection", "organizations", "mutation-operator")
	rawRequest("POST", "/api/collections/organizations/records", []byte(`{"id":"mutationorg001a","name":"Native child fixture","parent":"fixtureorg0001a","owner":"fixtureuser001a"}`), jsonHeaders, 200)
	defer request("DELETE", f.DataOrigin+"/api/collections/organizations/records/mutationorg001a", nil, true)
	revoke("mutation-create-org")
	code, b = request("GET", f.DataOrigin+"/api/collections/org_parent_map/records?perPage=1", nil, true)
	var mappings struct{ Items []struct{ ID string } }
	if code != 200 || json.Unmarshal(b, &mappings) != nil {
		t.Fatal("native org_parent_map listing")
	}
	if len(mappings.Items) != 1 || len(mappings.Items[0].ID) != 62 {
		t.Fatal("native organization hook must create a 62-character map ID")
	}
	id := mappings.Items[0].ID
	bind("mutation-long-id", "org_parent_map", id, "mutation-operator")
	for _, alias := range []string{"org_parent_map", "35180llsus0m925"} {
		rawRequest("GET", "/api/collections/"+alias+"/records/"+id, nil, http.Header{}, 200)
	}
	revoke("mutation-long-id")
	for _, alias := range []string{"org_parent_map", "35180llsus0m925"} {
		rawRequest("GET", "/api/collections/"+alias+"/records/"+id, nil, http.Header{}, 403)
	}
	t.Logf("native org_parent_map detail ID length %d verified", len(id))
	t.Log("180 mutation and 20 file routes denied unbound; exact CRUD, native relation write, JSON/multipart byte preservation, separate file GET/HEAD/Range authority and revoked writes passed")
	runPocketBaseExpansion(t, f.DataOrigin, rawRequest, request, bind, revoke, capture)
	runPocketBaseBatch(t, f.DataOrigin, rawRequest, request, bind, revoke, capture)
}

// Observe only the proxy's real native upstream transport, without replacing it.
type mutationCaptureTransport struct {
	base           http.RoundTripper
	origin         string
	mu             sync.Mutex
	body           []byte
	contentType    string
	calls          int
	decisions      int
	decisionReason string
	responseBytes  []byte
	afterResponse  func()
}

func (c *mutationCaptureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/api/v2/http-capabilities/decide" {
		c.mu.Lock()
		c.decisions++
		c.mu.Unlock()
	}
	if strings.HasPrefix(r.URL.String(), c.origin+"/") {
		c.mu.Lock()
		c.calls++
		c.mu.Unlock()
	}
	if strings.HasPrefix(r.URL.String(), c.origin+"/") && (r.Method == "POST" || r.Method == "PATCH") {
		b, e := io.ReadAll(r.Body)
		if e != nil {
			return nil, e
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(b))
		c.mu.Lock()
		c.body = append([]byte(nil), b...)
		c.contentType = r.Header.Get("Content-Type")
		c.mu.Unlock()
	}
	res, err := c.base.RoundTrip(r)
	if err == nil && r.URL.Path == "/api/v2/http-capabilities/decide" {
		b, e := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		res.Body.Close()
		if e != nil {
			return nil, e
		}
		res.Body = io.NopCloser(bytes.NewReader(b))
		var result struct{ Reason, Error string }
		if json.Unmarshal(b, &result) == nil {
			c.mu.Lock()
			c.decisionReason = result.Reason + " " + result.Error
			c.mu.Unlock()
		}
	}
	if err == nil && strings.HasPrefix(r.URL.String(), c.origin+"/") && r.URL.Query().Has("expand") {
		b, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
		res.Body.Close()
		if e != nil {
			return nil, e
		}
		res.Body = io.NopCloser(bytes.NewReader(b))
		c.mu.Lock()
		c.responseBytes = append([]byte(nil), b...)
		hook := c.afterResponse
		c.afterResponse = nil
		c.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	return res, err
}
func (c *mutationCaptureTransport) check(t *testing.T, want []byte, contentType string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !bytes.Equal(c.body, want) || c.contentType != contentType {
		t.Fatal("native upstream request body or Content-Type was rewritten")
	}
}
