package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

// The wrapper runs this separately after the original generation-2 fixture.
// Catalogs come from Grant's generator, rather than a second hand-written map.
func TestPocketBaseRemainingCollections(t *testing.T) {
	if os.Getenv("PATCH_AUTH_E2E_CONFIG") == "" || os.Getenv("PATCH_DATA_READ_CATALOG") == "" {
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
	raw, err = os.ReadFile(os.Getenv("PATCH_DATA_READ_CATALOG"))
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
	raw, err = os.ReadFile(os.Getenv("PATCH_DATA_READ_ACTIONS"))
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
	must("POST", org+"/roles", map[string]string{"id": "remaining-reader", "code": "remaining-reader", "name": "Explicit remaining records"})
	must("PUT", org+"/roles/remaining-reader/actions", map[string]any{"actionIds": actionIDs})
	must("POST", f.VoterURL+"/api/v1/admin/providers/"+f.ProviderID+"/http-capability-generations", map[string]any{"schemaVersion": 1, "generation": generated.Generation, "expectedLatestGeneration": previous.Generation, "capabilities": generated.Capabilities, "responseResources": generated.ResponseResources, "catalogDigest": generated.CatalogDigest})
	must("POST", f.VoterURL+"/api/v1/admin/providers/"+f.ProviderID+"/http-capability-active", map[string]any{"expectedGeneration": previous.Generation, "expectedCatalogDigest": previous.CatalogDigest, "targetGeneration": generated.Generation, "targetCatalogDigest": generated.CatalogDigest})
	proxy, err := New(config.ProxyConfig{CredentialMode: "pocketbase", PocketBaseIssuer: f.AuthOrigin, PocketBaseCollectionID: f.CollectionID, PocketBaseApplicationID: f.ApplicationID, ProviderID: f.ProviderID, PepClientID: f.PEPClientID, Origin: f.DataOrigin, ExpectedCatalogDigest: generated.CatalogDigest, AppAuthKey: f.GrantAppKey, AuthorizationMode: "service-token", UpstreamToken: f.UpstreamToken, MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20}, f.GrantURL, client, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(proxy.Handler())
	defer front.Close()
	checkList := func(path string, total, page int, want []string) {
		t.Helper()
		q := url.Values{"page": {fmt.Sprint(page)}, "perPage": {"1"}, "sort": {"id"}, "filter": {`id != "neverexists000a" || id = "remaining00003a"`}}
		code, b := request("GET", front.URL+path+"?"+q.Encode(), nil, false)
		var result struct {
			TotalItems, TotalPages int
			Items                  []struct{ ID string }
		}
		if code != 200 || json.Unmarshal(b, &result) != nil || result.TotalItems != total || result.TotalPages != total {
			t.Fatalf("%s status%d total%d pages%d want%d: %s", path, code, result.TotalItems, result.TotalPages, total, b)
		}
		got := []string{}
		for _, r := range result.Items {
			got = append(got, r.ID)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s IDs %v want %v", path, got, want)
		}
	}
	// Every generated alias reaches real PocketBase, with no implicit authority.
	must("POST", org+"/bindings", map[string]any{"id": "remaining-parent-plant", "subjectType": "user", "subjectId": owner.UserID, "subjectOrganizationId": f.OrganizationID, "providerId": f.ProviderID, "resourceType": "plant", "resourceId": "fixtureplant01a", "roleId": "remaining-reader", "agreementId": nil, "state": "active"})

	kinds := make([]string, 0, len(lists))
	for kind := range lists {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	for _, kind := range kinds {
		caps := lists[kind]
		if len(caps) != 2 {
			t.Fatalf("%s aliases %d", kind, len(caps))
		}
		if kind == "plant" {
			continue
		}
		for _, c := range caps {
			checkList(c.PathTemplate, 0, 1, nil)
			code, _ := request("GET", front.URL+c.PathTemplate+"/fixtureplant01a", nil, false)
			if code != 403 {
				t.Fatalf("%s implicit plant authority status%d", kind, code)
			}
		}
	}
	ids := []string{"remaining00001a", "remaining00002a", "remaining00003a"}
	for _, collection := range []string{"plants", "permissions", "panelmaps", "blueprints"} {
		for _, id := range ids {
			payload := map[string]any{"id": id}
			switch collection {
			case "plants":
				payload["name"] = "Remaining " + id
				payload["organization"] = "fixtureorg0001a"
				payload["permission"] = "fixtureperm001a"
			case "panelmaps", "blueprints":
				payload["plant"] = id
				payload["data"] = map[string]any{"fixture": true}
				if collection == "blueprints" {
					payload["date"] = "2026-09-09 00:00:00.000Z"
				}
			case "permissions":
				payload["plant"] = id
			}
			code, b := request("POST", f.DataOrigin+"/api/collections/"+collection+"/records", payload, true)
			if code != 200 {
				t.Fatalf("seed %s status%d: %s", collection, code, b)
			}
			defer request("DELETE", f.DataOrigin+"/api/collections/"+collection+"/records/"+id, nil, true)
		}
	}
	for _, kind := range []string{"permissions", "panelmaps", "blueprints", "plants_viewer", "temporary_plants", "panelmaps_viewer", "temporary_panelmaps", "blueprints_viewer", "temporary_blueprints"} {
		t.Run(kind, func(t *testing.T) {
			caps := lists[kind]
			for i, id := range ids[:2] {
				must("POST", org+"/bindings", map[string]any{"id": fmt.Sprintf("remaining-%s-%d", kind, i), "subjectType": "user", "subjectId": owner.UserID, "subjectOrganizationId": f.OrganizationID, "providerId": f.ProviderID, "resourceType": kind, "resourceId": id, "roleId": "remaining-reader", "agreementId": nil, "state": "active"})
			}
			for _, c := range caps {
				checkList(c.PathTemplate, 2, 1, ids[:1])
				checkList(c.PathTemplate, 2, 2, ids[1:2])
				for i, id := range ids {
					code, _ := request("GET", front.URL+c.PathTemplate+"/"+id, nil, false)
					want := 200
					if i == 2 {
						want = 403
					}
					if code != want {
						t.Fatalf("detail %s %s status%d want%d", kind, id, code, want)
					}
				}
				code, _ := request("GET", front.URL+c.PathTemplate+"?expand=unmapped_relation", nil, false)
				if code != 422 {
					t.Fatalf("expand status%d", code)
				}
			}
			for i := range ids[:2] {
				must("DELETE", org+"/bindings/"+fmt.Sprintf("remaining-%s-%d", kind, i), nil)
			}
			for _, c := range caps {
				checkList(c.PathTemplate, 0, 1, nil)
				code, _ := request("GET", front.URL+c.PathTemplate+"/"+ids[0], nil, false)
				if code != 403 {
					t.Fatalf("revoked detail status%d", code)
				}
			}
		})
	}
	t.Log("42 generated collections validated; 41 unbound collections denied by both aliases; 3 remaining base and 6 view namespaces passed real Grant allow/deny/revoke/detail/list/page/count")
}
