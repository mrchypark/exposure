package capability

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func runPocketBaseExpansion(t *testing.T, origin string, rawRequest func(string, string, []byte, http.Header, int) []byte, request func(string, string, any, bool) (int, []byte), bind func(string, string, string, string), revoke func(string), capture *mutationCaptureTransport) {
	t.Helper()
	ids := []string{"expandplant001a", "expandplant002a"}
	for _, id := range ids {
		code, b := request("POST", origin+"/api/collections/plants/records", map[string]any{"id": id, "name": "Expanded root " + id, "organization": "fixtureorg0001a", "permission": "fixtureperm001a"}, true)
		if code != 200 {
			t.Fatalf("expansion seed status%d %s", code, b)
		}
		defer request("DELETE", origin+"/api/collections/plants/records/"+id, nil, true)
	}
	get := func(path string, status, decisions int) []byte {
		t.Helper()
		capture.mu.Lock()
		before := capture.decisions
		beforeUpstream := capture.calls
		capture.mu.Unlock()
		b := rawRequest("GET", path, nil, http.Header{}, status)
		capture.mu.Lock()
		count := capture.decisions - before
		upstream := capture.calls - beforeUpstream
		native := append([]byte(nil), capture.responseBytes...)
		capture.mu.Unlock()
		if count != decisions {
			t.Fatalf("expansion decisions%d want%d", count, decisions)
		}
		if status == 200 {
			if upstream != 1 || !bytes.Equal(b, native) {
				t.Fatal("authorized expansion changed native bytes or request count")
			}
		}
		if status == 403 && bytes.Contains(b, []byte("Synthetic")) {
			t.Fatal("denied expansion leaked native body")
		}
		return b
	}
	detail := "/api/collections/plants/records/" + ids[0] + "?expand=organization"
	get(detail, 403, 1)
	bind("expand-root-one", "plant", ids[0], "mutation-operator")
	get(detail, 403, 2) // root grant does not grant organization expansion
	bind("expand-organization", "organizations", "fixtureorg0001a", "mutation-operator")
	get(detail, 200, 2)
	get("/api/collections/30hrtar148uy66c/records/"+ids[0]+"?expand=organization", 200, 2)
	nested := "/api/collections/plants/records/" + ids[0] + "?expand=organization.owner"
	get(nested, 403, 2)
	bind("expand-profile", "users", "fixtureuser001a", "mutation-operator")
	get(nested, 200, 2)
	// Arrays use the same graph, including each returned related record.
	code, b := request("POST", origin+"/api/collections/permissions/records", map[string]any{"id": "expandpermis01a", "plant": ids[0], "users": []string{"fixtureuser001a"}}, true)
	if code != 200 {
		t.Fatalf("array expansion seed%d %s", code, b)
	}
	defer request("DELETE", origin+"/api/collections/permissions/records/expandpermis01a", nil, true)
	bind("expand-array-root", "permissions", "expandpermis01a", "mutation-operator")
	arrayPath := "/api/collections/permissions/records/expandpermis01a?expand=users"
	get(arrayPath, 200, 2)
	revoke("expand-profile")
	get(arrayPath, 403, 2)
	get(nested, 403, 2)
	bind("expand-profile-again", "users", "fixtureuser001a", "mutation-operator")
	// Lists keep native counts and pagination, and recheck only returned roots.
	bind("expand-root-two", "plant", ids[1], "mutation-operator")
	for _, page := range []string{"1", "2"} {
		q := url.Values{"expand": {"organization"}, "filter": {`id="expandplant001a" || id="expandplant002a"`}, "page": {page}, "perPage": {"1"}, "sort": {"id"}}
		b := get("/api/collections/plants/records?"+q.Encode(), 200, 2)
		var list struct {
			TotalItems, TotalPages int
			Items                  []json.RawMessage
		}
		if json.Unmarshal(b, &list) != nil || list.TotalItems != 2 || list.TotalPages != 2 || len(list.Items) != 1 {
			t.Fatal("expanded pagination/count changed")
		}
	}
	get("/api/collections/plants/records?expand=organization&filter="+url.QueryEscape(`id="doesnotexist001"`), 200, 2)
	revoke("expand-organization")
	get(detail, 403, 2)
	bind("expand-organization-again", "organizations", "fixtureorg0001a", "mutation-operator")
	// Revoke after native fetch but before its bytes leave Exposure.
	capture.mu.Lock()
	capture.afterResponse = func() { revoke("expand-root-one") }
	capture.mu.Unlock()
	get(detail, 403, 2)
	get(detail, 403, 1)
	// Missing/null relations and native errors preserve their original semantics.
	code, b = request("POST", origin+"/api/collections/permissions/records", map[string]any{"id": "expandempty001a", "plant": ids[1]}, true)
	if code != 200 {
		t.Fatalf("empty expansion seed%d %s", code, b)
	}
	defer request("DELETE", origin+"/api/collections/permissions/records/expandempty001a", nil, true)
	bind("expand-empty", "permissions", "expandempty001a", "mutation-operator")
	get("/api/collections/permissions/records/expandempty001a?expand=users", 200, 2)
	bind("expand-missing", "plant", "expandmissing1a", "mutation-operator")
	get("/api/collections/plants/records/expandmissing1a?expand=organization", 404, 1)
	t.Log("actual expansion: root/related/nested/array independent grants, revocation after fetch, identical native bytes and page counts, empty lists/relations, and native404 passed")
}
