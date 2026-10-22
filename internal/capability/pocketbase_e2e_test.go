package capability

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
)

// This optional test uses actual independently started PocketBase, Grant and
// patch-data servers. Credentials live in a private temporary fixture file.
func TestPocketBaseLocalEndToEnd(t *testing.T) {
	path := os.Getenv("PATCH_AUTH_E2E_CONFIG")
	if path == "" {
		t.Skip("set PATCH_AUTH_E2E_CONFIG to an isolated local fixture JSON file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		PrivateDataOrigin, VoterURL, ManagementPDPURL                           string
		ManagementApplicationID, ManagementPEPClientID, ManagementCatalogDigest string
		UpstreamToken                                                           string
		AuthOrigin, Collection, CollectionID, ApplicationID                     string
		AllowIdentity, AllowPassword, DenyIdentity, DenyPassword                string
		GrantURL, GrantAppKey, ProviderID, PEPClientID, CatalogDigest           string
		DataOrigin, ResourcePath, OrganizationID, DisabledLoginPath             string
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{f.AuthOrigin, f.GrantURL, f.DataOrigin} {
		u, e := url.Parse(origin)
		if e != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
			t.Fatal("e2e requires explicit loopback origins")
		}
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(method, target, token string, body []byte) (int, []byte) {
		t.Helper()
		r, e := http.NewRequest(method, target, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("X-Organization-ID", f.OrganizationID)
		}
		res, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if e != nil {
			t.Fatal(e)
		}
		return res.StatusCode, b
	}
	login := func(identity, password string, wantSuccess bool) string {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"identity": identity, "password": password})
		status, b := request("POST", f.AuthOrigin+"/api/collections/"+url.PathEscape(f.Collection)+"/auth-with-password", "", body)
		if !wantSuccess {
			if status < 400 {
				t.Fatalf("wrong password login status=%d", status)
			}
			return ""
		}
		var out struct {
			Token string `json:"token"`
		}
		if status != 200 || json.Unmarshal(b, &out) != nil || out.Token == "" {
			t.Fatalf("PocketBase login status=%d", status)
		}
		return out.Token
	}
	allow := login(f.AllowIdentity, f.AllowPassword, true)
	deny := login(f.DenyIdentity, f.DenyPassword, true)
	login(f.AllowIdentity, "incorrect-local-fixture-password", false)
	cfg := config.ProxyConfig{CredentialMode: "pocketbase", PocketBaseIssuer: f.AuthOrigin, PocketBaseCollectionID: f.CollectionID, PocketBaseApplicationID: f.ApplicationID, ProviderID: f.ProviderID, PepClientID: f.PEPClientID, Origin: f.DataOrigin, ExpectedCatalogDigest: f.CatalogDigest, AppAuthKey: f.GrantAppKey, MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20, AuthnLimiterKey: "local-fixture-only", PublicAuthnGlobalCapacity: 10, PublicAuthnPeerCapacity: 10, PublicAuthnGlobalRefill: time.Second, PublicAuthnPeerRefill: time.Second}
	cfg.AuthorizationMode = "service-token"
	cfg.UpstreamToken = f.UpstreamToken
	p, err := New(cfg, f.GrantURL, client, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(p.Handler())
	defer proxy.Close()
	status, allowedBody := request("GET", proxy.URL+f.ResourcePath, allow, nil)
	if status != 200 {
		t.Fatalf("allowed resource status=%d", status)
	}
	if f.PrivateDataOrigin != "" {
		status, originalBody := request("GET", f.PrivateDataOrigin+f.ResourcePath, f.UpstreamToken, nil)
		if status != 200 || !bytes.Equal(originalBody, allowedBody) {
			t.Fatalf("native PocketBase response changed: status=%d", status)
		}
	}
	if status, _ := request("GET", proxy.URL+f.ResourcePath, deny, nil); status != 403 {
		t.Fatalf("unassigned user status=%d", status)
	}
	parts := strings.Split(allow, ".")
	if len(parts) != 3 {
		t.Fatal("PocketBase returned non-JWT credential")
	}
	signature, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil || len(signature) == 0 {
		t.Fatal("invalid signature encoding")
	}
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	if status, _ := request("GET", proxy.URL+f.ResourcePath, strings.Join(parts, "."), nil); status != 401 {
		t.Fatalf("forged credential status=%d", status)
	}
	if status, _ := request("GET", proxy.URL+f.ResourcePath, "", nil); status != 401 {
		t.Fatalf("missing credential status=%d", status)
	}
	body, _ := json.Marshal(map[string]string{"identity": f.AllowIdentity, "password": f.AllowPassword})
	if f.DisabledLoginPath == "" {
		t.Fatal("disabled legacy login path required")
	}
	privateData := f.PrivateDataOrigin
	if privateData == "" {
		privateData = f.DataOrigin
	}
	if status, _ := request("POST", privateData+f.DisabledLoginPath, "", body); status != 404 {
		t.Fatalf("patch-data login must be removed, status=%d", status)
	}
	if f.ManagementPDPURL != "" {
		management := cfg
		management.AuthorizationMode = "forward-user"
		management.UpstreamToken = ""
		management.Origin = f.VoterURL
		management.ProviderID = "grant-management"
		management.PepClientID = f.ManagementPEPClientID
		management.PocketBaseApplicationID = f.ManagementApplicationID
		management.ExpectedCatalogDigest = f.ManagementCatalogDigest
		mp, err := New(management, f.ManagementPDPURL, client, 4)
		if err != nil {
			t.Fatal(err)
		}
		if err = mp.Refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		ms := httptest.NewServer(mp.Handler())
		defer ms.Close()
		groups := ms.URL + "/api/v1/orgs/" + f.OrganizationID + "/groups"
		if status, _ := request("GET", groups, allow, nil); status != 200 {
			t.Fatalf("management list status=%d", status)
		}
		if status, _ := request("GET", groups, deny, nil); status != 403 {
			t.Fatalf("management unauthorized status=%d", status)
		}
		if status, _ := request("POST", groups, allow, []byte(`{"id":"e2e-managed-group","name":"Managed via Exposure","description":null}`)); status != 201 {
			t.Fatalf("management create status=%d", status)
		}
		if status, b := request("DELETE", groups+"/e2e-managed-group", allow, nil); status != 204 || len(b) != 0 {
			t.Fatalf("management delete status=%d bodylength=%d", status, len(b))
		}
		if status, _ := request("POST", groups, allow, []byte(`{"id":"invalid","name":null,"description":null}`)); status != 422 {
			t.Fatalf("management upstream422 status=%d", status)
		}
		if status, _ := request("POST", ms.URL+"/api/v1/admin/bootstrap/owner", allow, nil); status != 404 {
			t.Fatalf("private bootstrap published status=%d", status)
		}
		// Revoke only the task's seeded data binding through the authoritative API.
		if status, _ := request("DELETE", f.VoterURL+"/api/v1/orgs/"+f.OrganizationID+"/bindings/fixture-binding", allow, nil); status != 204 {
			t.Fatalf("fixture revocation status=%d", status)
		}
		if status, _ := request("GET", proxy.URL+f.ResourcePath, allow, nil); status != 403 {
			t.Fatalf("revoked binding still allowed: %d", status)
		}
		t.Log("separate management Exposure create/list/delete and API422, private bootstrap exclusion, immediate replica-backed revocation verified")
	}
	t.Log("actual PocketBase login success/failure, Grant-backed Exposure allow/deny, forged/missing token, and removed patch-data login verified")
}
