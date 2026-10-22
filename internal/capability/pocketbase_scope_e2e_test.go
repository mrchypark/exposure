package capability

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

// Uses actual PocketBase auth/data, the Grant voter, and the fenced learner.
// All synthetic authority is seeded through Grant APIs, never direct SQL.
func TestPocketBaseGrantScopedList(t *testing.T) {
	fixture := os.Getenv("PATCH_AUTH_E2E_CONFIG")
	if fixture == "" {
		t.Skip("set isolated native fixture")
	}
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ AuthOrigin, CollectionID, AllowIdentity, AllowPassword, DataOrigin, VoterURL, GrantURL, GrantMasterKeyFile, GrantAppKey, ProviderID, PEPClientID, CatalogDigest, ApplicationID, OrganizationID, UpstreamToken string }
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("invalid fixture")
	}
	for _, origin := range []string{f.AuthOrigin, f.DataOrigin, f.VoterURL, f.GrantURL} {
		u, e := url.Parse(origin)
		if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
			t.Fatal("loopback fixture required")
		}
	}
	master, e := os.ReadFile(f.GrantMasterKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	token := ""
	request := func(method, target string, v any, service bool) (int, []byte) {
		t.Helper()
		var b []byte
		if v != nil {
			b, _ = json.Marshal(v)
		}
		r, _ := http.NewRequest(method, target, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Organization-ID", f.OrganizationID)
		if service {
			r.Header.Set("Authorization", f.UpstreamToken)
		} else {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if strings.HasPrefix(target, f.VoterURL+"/") {
			r.Header.Set("X-Grant-Master-Key", strings.TrimSpace(string(master)))
			r.Header.Set("X-Grant-App-Auth-Key", f.GrantAppKey)
			addGrantActionPrecondition(t, client, r)
		}
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		out, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
		if e != nil {
			t.Fatal(e)
		}
		return res.StatusCode, out
	}
	code, b := request("POST", f.AuthOrigin+"/api/collections/users/auth-with-password", map[string]string{"identity": f.AllowIdentity, "password": f.AllowPassword}, false)
	var login struct{ Token string }
	if code != 200 || json.Unmarshal(b, &login) != nil || login.Token == "" {
		t.Fatalf("login status%d", code)
	}
	token = login.Token
	code, b = request("POST", f.VoterURL+"/api/v1/admin/bootstrap/owner", map[string]string{"organizationId": f.OrganizationID}, false)
	var owner struct {
		UserID string `json:"userId"`
	}
	if (code != 200 && code != 201) || json.Unmarshal(b, &owner) != nil || owner.UserID == "" {
		t.Fatalf("bootstrap status%d", code)
	}
	// Two equally visible native records, only one receives an explicit Grant binding.
	for _, id := range []string{"scopeplant0001a", "scopeplant0002a"} {
		code, _ = request("POST", f.DataOrigin+"/api/collections/plants/records", map[string]string{"id": id, "name": "Scoped native plant " + id, "organization": "fixtureorg0001a", "permission": "fixtureperm001a"}, true)
		if code != 200 {
			t.Fatalf("native seed%d", code)
		}
		defer request("DELETE", f.DataOrigin+"/api/collections/plants/records/"+id, nil, true)
	}
	code, _ = request("POST", f.VoterURL+"/api/v1/orgs/"+f.OrganizationID+"/bindings", map[string]any{"id": "scope-fixture-binding", "subjectType": "user", "subjectId": owner.UserID, "subjectOrganizationId": f.OrganizationID, "providerId": f.ProviderID, "resourceType": "plant", "resourceId": "scopeplant0001a", "roleId": "fixture-reader", "agreementId": nil, "state": "active"}, false)
	if code != 201 && code != 200 {
		t.Fatalf("binding status%d", code)
	}
	capRaw, e := os.ReadFile("../../scripts/testdata/pocketbase-plants-list.json")
	if e != nil {
		t.Fatal(e)
	}
	var cap capability
	if json.Unmarshal(capRaw, &cap) != nil {
		t.Fatal("invalid list fixture")
	}
	cap.ContractDigest = capabilityDigest(cap)
	alias := cap
	alias.CapabilityID = "plants.list.id"
	alias.PathTemplate = "/api/collections/30hrtar148uy66c/records"
	alias.ContractDigest = capabilityDigest(alias)
	catalog := &catalog{SchemaVersion: 1, ProviderID: f.ProviderID, Generation: 2, Capabilities: []capability{cap, alias}}
	// Explicit synthetic file permissions exercise multipart and binary transport
	// against real Grant, independently of the controlled-PDP transport fixture.
	code, _ = request("PUT", f.VoterURL+"/api/v1/admin/providers/"+f.ProviderID+"/actions", map[string]any{"actions": []map[string]any{{"id": "plant.read", "code": "plant.read", "name": "Read plant", "riskLevel": "low", "visibilityGranting": false, "grantableToApplications": true}, {"id": "file.read", "code": "file.read", "name": "Fixture file read", "riskLevel": "low", "visibilityGranting": false, "grantableToApplications": true}, {"id": "file.write", "code": "file.write", "name": "Fixture file write", "riskLevel": "low", "visibilityGranting": false, "grantableToApplications": true}}}, false)
	if code != 200 {
		t.Fatalf("file actions status%d", code)
	}
	code, _ = request("PUT", f.VoterURL+"/api/v1/admin/orgs/"+f.OrganizationID+"/apps/"+f.ApplicationID+"/trust", map[string]bool{"trusted": false}, false)
	if code != 200 {
		t.Fatalf("untrust fixture app%d", code)
	}
	code, _ = request("PUT", f.VoterURL+"/api/v1/orgs/"+f.OrganizationID+"/apps/"+f.ApplicationID+"/actions", map[string]any{"actionIds": []string{"patch-data.plant.read", "patch-data.file.read", "patch-data.file.write"}}, false)
	if code != 200 {
		t.Fatalf("file app scope status%d", code)
	}
	code, _ = request("PUT", f.VoterURL+"/api/v1/admin/orgs/"+f.OrganizationID+"/apps/"+f.ApplicationID+"/trust", map[string]bool{"trusted": true}, false)
	if code != 200 {
		t.Fatalf("trust fixture app%d", code)
	}
	code, _ = request("POST", f.VoterURL+"/api/v1/orgs/"+f.OrganizationID+"/roles", map[string]string{"id": "fixture-file-role", "code": "fixture-file-role", "name": "Fixture files"}, false)
	if code != 201 && code != 200 {
		t.Fatalf("file role status%d", code)
	}
	code, _ = request("PUT", f.VoterURL+"/api/v1/orgs/"+f.OrganizationID+"/roles/fixture-file-role/actions", map[string]any{"actionIds": []string{"patch-data.file.read", "patch-data.file.write"}}, false)
	if code != 200 {
		t.Fatalf("file role actions status%d", code)
	}
	bindFile := func(binding, kind, id string) {
		t.Helper()
		code, _ := request("POST", f.VoterURL+"/api/v1/orgs/"+f.OrganizationID+"/bindings", map[string]any{"id": binding, "subjectType": "user", "subjectId": owner.UserID, "subjectOrganizationId": f.OrganizationID, "providerId": f.ProviderID, "resourceType": kind, "resourceId": id, "roleId": "fixture-file-role", "agreementId": nil, "state": "active"}, false)
		if code != 201 && code != 200 {
			t.Fatalf("file binding status%d", code)
		}
	}
	bindFile("file-collection-binding", "collection", "files")
	writeAction, readAction := "patch-data.file.write", "patch-data.file.read"
	fileResponse := responsePolicy{MaxBytes: 1 << 20, ForwardHeaders: []string{"content-range", "content-type", "last-modified"}, Redirects: "deny", ErrorStatuses: []int{304, 400, 403, 404, 412, 416}}
	uploadCap := capability{CapabilityID: "files.upload", Version: 1, Enabled: true, AccessMode: "authorized", Method: "POST", PathTemplate: "/api/collections/files/records", ActionID: &writeAction, Resource: &resource{Type: "collection", ID: extractor{Kind: "constant", Value: "files"}}, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "multipart", MaxBytes: 1 << 20, ForwardHeaders: []string{"content-type"}, Authorization: "service-token", ContentTypes: []string{"multipart/form-data"}}, Response: fileResponse}
	downloadCap := capability{CapabilityID: "files.download", Version: 1, Enabled: true, AccessMode: "authorized", Method: "GET", PathTemplate: "/api/files/pbc_3446931122/{id}/{filename}", ActionID: &readAction, Resource: &resource{Type: "file", ID: extractor{Kind: "pathSegment", Name: "id", Format: "pocketbaseId"}}, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "none", ForwardHeaders: []string{"range"}, Authorization: "service-token"}, Response: fileResponse, PathParameters: []pathParameter{{Name: "filename", Format: "utf8Segment", MaxBytes: 1024}}}
	for _, c := range []capability{uploadCap, downloadCap} {
		c.ContractDigest = capabilityDigest(c)
		catalog.Capabilities = append(catalog.Capabilities, c)
	}
	catalog.CatalogDigest = catalogDigest(catalog)
	code, b = request("POST", f.VoterURL+"/api/v1/admin/providers/"+f.ProviderID+"/http-capability-generations", map[string]any{"schemaVersion": 1, "generation": 2, "expectedLatestGeneration": 1, "capabilities": catalog.Capabilities, "catalogDigest": catalog.CatalogDigest}, false)
	if code != 200 && code != 201 {
		t.Fatalf("stage status%d: %s", code, b)
	}
	code, _ = request("POST", f.VoterURL+"/api/v1/admin/providers/"+f.ProviderID+"/http-capability-active", map[string]any{"expectedGeneration": 1, "expectedCatalogDigest": f.CatalogDigest, "targetGeneration": 2, "targetCatalogDigest": catalog.CatalogDigest}, false)
	if code != 200 {
		t.Fatalf("activate status%d", code)
	}
	cfg := config.ProxyConfig{CredentialMode: "pocketbase", PocketBaseIssuer: f.AuthOrigin, PocketBaseCollectionID: f.CollectionID, PocketBaseApplicationID: f.ApplicationID, ProviderID: f.ProviderID, PepClientID: f.PEPClientID, Origin: f.DataOrigin, ExpectedCatalogDigest: catalog.CatalogDigest, AppAuthKey: f.GrantAppKey, AuthorizationMode: "service-token", UpstreamToken: f.UpstreamToken, MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20}
	proxy, e := New(cfg, f.GrantURL, client, 4)
	if e != nil {
		t.Fatal(e)
	}
	if e = proxy.Refresh(t.Context()); e != nil {
		t.Fatal(e)
	}
	front := httptest.NewServer(proxy.Handler())
	defer front.Close()
	var multipartBytes bytes.Buffer
	mw := multipart.NewWriter(&multipartBytes)
	part, e := mw.CreateFormFile("file", "résumé.txt")
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte("real Grant authorized native file bytes\n")
	_, _ = part.Write(payload)
	_ = mw.Close()
	uploadReq, _ := http.NewRequest("POST", front.URL+uploadCap.PathTemplate, bytes.NewReader(multipartBytes.Bytes()))
	uploadReq.Header.Set("Content-Type", mw.FormDataContentType())
	uploadReq.Header.Set("Authorization", "Bearer "+token)
	uploadReq.Header.Set("X-Organization-ID", f.OrganizationID)
	uploadRes, e := client.Do(uploadReq)
	if e != nil {
		t.Fatal(e)
	}
	uploadBody, _ := io.ReadAll(io.LimitReader(uploadRes.Body, 1<<20))
	uploadRes.Body.Close()
	var fileRecord struct{ ID, File string }
	if uploadRes.StatusCode != 200 || json.Unmarshal(uploadBody, &fileRecord) != nil || fileRecord.ID == "" {
		t.Fatalf("real Grant multipart status%d", uploadRes.StatusCode)
	}
	defer request("DELETE", f.DataOrigin+"/api/collections/files/records/"+fileRecord.ID, nil, true)
	bindFile("file-record-binding", "file", fileRecord.ID)
	code, b = request("GET", front.URL+"/api/files/pbc_3446931122/"+fileRecord.ID+"/"+url.PathEscape(fileRecord.File), nil, false)
	if code != 200 || !bytes.Equal(b, payload) {
		t.Fatalf("real Grant binary download status%d", code)
	}
	list := func(path string, want int) {
		t.Helper()
		code, b := request("GET", front.URL+path, nil, false)
		var result struct {
			TotalItems int `json:"totalItems"`
			TotalPages int `json:"totalPages"`
			Items      []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if code != 200 || json.Unmarshal(b, &result) != nil || result.TotalItems != want || len(result.Items) != want {
			t.Fatalf("scoped native pagination status%d count%d items%d want%d", code, result.TotalItems, len(result.Items), want)
		}
		if want == 1 && result.Items[0].ID != "scopeplant0001a" {
			t.Fatal("unauthorized record exposed")
		}
	}
	filter := url.QueryEscape(`name ~ "Scoped" || id = "scopeplant0002a"`)
	for _, path := range []string{cap.PathTemplate, alias.PathTemplate} {
		list(path+"?page=1&perPage=1&sort=-name&filter="+filter, 1)
	}
	code, _ = request("GET", front.URL+cap.PathTemplate+"?filter="+url.QueryEscape(`name='x') || true = true || (name='y'`), nil, false)
	if code != 422 {
		t.Fatalf("filter breakout status%d", code)
	}
	code, _ = request("GET", front.URL+cap.PathTemplate+"?expand=organization", nil, false)
	if code != 422 {
		t.Fatalf("unmapped expansion status%d", code)
	}
	code, _ = request("DELETE", f.VoterURL+"/api/v1/orgs/"+f.OrganizationID+"/bindings/scope-fixture-binding", nil, false)
	if code != 204 {
		t.Fatalf("revoke status%d", code)
	}
	list(cap.PathTemplate+"?page=1&perPage=1&filter="+filter, 0)
	t.Log("real Grant learner scope: aliases, OR intersection, native pagination, malformed filter, expansion deny, revocation and empty list passed")
}
