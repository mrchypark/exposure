package capability

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestManagementCatalogCanonicalFixture(t *testing.T) {
	b, err := os.ReadFile("../../scripts/testdata/grant-management-capability.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion uint64       `json:"schemaVersion"`
		Generation    uint64       `json:"generation"`
		Capabilities  []capability `json:"capabilities"`
		CatalogDigest string       `json:"catalogDigest"`
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Capabilities {
		if err = validateCapability(c); err != nil {
			t.Fatal(err)
		}
		if capabilityDigest(c) != c.ContractDigest {
			t.Fatal("fixture contract differs from wire canonical digest")
		}
	}
	c := catalog{SchemaVersion: fixture.SchemaVersion, ProviderID: "grant-management", Generation: fixture.Generation, Capabilities: fixture.Capabilities}
	if catalogDigest(&c) != fixture.CatalogDigest {
		t.Fatal("fixture catalog differs from wire canonical digest")
	}
}

func TestMultipleUniquePathParameters(t *testing.T) {
	if !validScalar("asciiToken", "org:one.two") || validScalar("asciiToken", strings.Repeat("a", 257)) {
		t.Fatal("ASCII resource scalar differs from path token contract")
	}
	template := "/orgs/{organizationId}/groups/{groupId}"
	captures, ok := matchTemplate(template, "/orgs/org-1/groups/group:2")
	if !ok || captures["organizationId"] != "org-1" || captures["groupId"] != "group:2" {
		t.Fatal("multiple parameters did not bind")
	}
	if _, ok := matchTemplate("/{id}/{id}", "/first/second"); ok {
		t.Fatal("duplicate parameter accepted")
	}
	for _, bad := range []string{".", "..", "%2f", "with space", strings.Repeat("a", 257)} {
		if _, ok := matchTemplate(template, "/orgs/org-1/groups/"+bad); ok {
			t.Fatal("unbounded/noncanonical capture accepted")
		}
	}
}
