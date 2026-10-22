package capability

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/exposure/internal/config"
)

func TestPocketBaseCredentialHintsAreDeploymentScoped(t *testing.T) {
	cfg := config.ProxyConfig{CredentialMode: "pocketbase", PocketBaseIssuer: "http://127.0.0.1:8091", PocketBaseCollectionID: "auth_users", PocketBaseApplicationID: "app-patch-auth"}
	for _, tc := range []struct {
		name, claims string
		valid        bool
	}{
		{"auth", `{"id":"record1","collectionId":"auth_users","type":"auth","iss":"https://attacker.invalid","sub":"ignored","client_id":"ignored"}`, true},
		{"wrong collection", `{"id":"record1","collectionId":"other","type":"auth"}`, false},
		{"wrong token type", `{"id":"record1","collectionId":"auth_users","type":"passwordReset"}`, false},
		{"scope delimiter", `{"id":"a/b","collectionId":"auth_users","type":"auth"}`, false},
		{"missing id", `{"collectionId":"auth_users","type":"auth"}`, false},
		{"duplicate id", `{"id":"record1","id":"record2","collectionId":"auth_users","type":"auth"}`, false},
		{"rauthy only", `{"sub":"user1","client_id":"client1"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/items/one", nil)
			token := "header." + base64.RawURLEncoding.EncodeToString([]byte(tc.claims)) + ".signature"
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("X-Organization-ID", "org1")
			auth, org, subject, audience, err := bearerIdentity(r, cfg)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && (auth != "Bearer "+token || org != "org1" || subject != "pocketbase:http://127.0.0.1:8091/auth_users/record1" || audience != "app-patch-auth") {
				t.Fatalf("unexpected scoped hints %q %q", subject, audience)
			}
		})
	}
}
