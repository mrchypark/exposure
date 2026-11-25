package capability

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type handlerPDP struct {
	pdppb.UnimplementedPolicyDecisionPointServer
	mode  string
	calls atomic.Int64
}

func (p *handlerPDP) DecideHttp(_ context.Context, req *pdppb.DecisionRequest) (*pdppb.DecisionResponse, error) {
	p.calls.Add(1)
	if p.mode == "unavailable" {
		return nil, status.Error(codes.Unavailable, "unavailable")
	}
	var in map[string]any
	if err := json.Unmarshal(req.EvidenceJson, &in); err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad evidence")
	}
	cred, ok := in["providerCredential"].(map[string]any)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing credential")
	}
	now := time.Now().UTC()
	out := map[string]any{"allowed": p.mode != "deny", "reason": "test", "actionId": "provider.item.read", "principalDigest": strings.Repeat("a", 64), "providerSubject": cred["subject"], "providerAudience": cred["audience"], "issuedAt": now.Format(time.RFC3339Nano), "expiresAt": now.Add(3 * time.Second).Format(time.RFC3339Nano)}
	for _, key := range []string{"providerId", "pepClientId", "catalogGeneration", "catalogDigest", "capabilityId", "capabilityVersion", "contractDigest", "resourceType", "resourceId", "method", "canonicalPath", "canonicalQueryDigest", "forwardedHeaderDigest", "bodyDigest", "bodyLength", "providerCredentialDigest", "requestBinding"} {
		out[key] = in[key]
	}
	if p.mode == "tamper" {
		out["requestBinding"] = "different"
	}
	if p.mode == "expired" {
		out["issuedAt"] = now.Add(-2 * time.Second).Format(time.RFC3339Nano)
		out["expiresAt"] = now.Add(-time.Second).Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal")
	}
	return &pdppb.DecisionResponse{DecisionJson: b}, nil
}

func TestGRPCProxyHandlerFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		mode             string
		status, upstream int
	}{{"allow", 200, 1}, {"deny", 403, 0}, {"tamper", 502, 0}, {"expired", 502, 0}, {"unavailable", 502, 0}} {
		t.Run(tc.mode, func(t *testing.T) {
			var upstream, fallback atomic.Int64
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/v2/http-capabilities/") {
					fallback.Add(1)
					http.Error(w, "unexpected fallback", 500)
					return
				}
				upstream.Add(1)
				_, _ = w.Write([]byte(`{"business":"visible"}`))
			}))
			defer httpServer.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer()
			fake := &handlerPDP{mode: tc.mode}
			pdppb.RegisterPolicyDecisionPointServer(server, fake)
			go server.Serve(listener)
			defer server.Stop()
			action := "provider.item.read"
			cap := capability{CapabilityID: "item.read", Version: 1, Enabled: true, AccessMode: "authorized", Method: "GET", PathTemplate: "/items/{id}", ActionID: &action, Resource: &resource{Type: "item", ID: extractor{Kind: "pathSegment", Name: "id", Format: "asciiToken"}}, Query: queryPolicy{Mode: "none"}, Request: requestPolicy{Body: "none"}, Response: responsePolicy{MaxBytes: 1024, Redirects: "deny"}, ContractDigest: "sha256:" + strings.Repeat("b", 64)}
			p, err := New(config.ProxyConfig{ProviderID: "provider", PepClientID: "pep", AppAuthKey: "key", Origin: httpServer.URL, MaxRequestBytes: 1024, MaxResponseBytes: 1024, AuthnLimiterKey: "k", PublicAuthnGlobalCapacity: 1, PublicAuthnPeerCapacity: 1, PublicAuthnGlobalRefill: time.Hour, PublicAuthnPeerRefill: time.Hour}, httpServer.URL, httpServer.Client(), 4)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.ConfigureGRPCLearner(listener.Addr().String(), "", "", time.Second); err != nil {
				t.Fatal(err)
			}
			defer p.CloseGRPCLearner()
			p.active = &catalog{SchemaVersion: 1, ProviderID: "provider", PepClientID: "pep", Generation: 1, CatalogDigest: "sha256:" + strings.Repeat("c", 64), Capabilities: []capability{cap}, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
			req := httptest.NewRequest(http.MethodGet, "/items/abc", nil)
			req.Header.Set("Authorization", "Bearer "+jwtWithExtraClaims(t))
			req.Header.Set("X-Organization-ID", "org")
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, req)
			if w.Code != tc.status || upstream.Load() != int64(tc.upstream) || fallback.Load() != 0 || fake.calls.Load() != 1 {
				t.Fatalf("status=%d upstream=%d fallback=%d calls=%d", w.Code, upstream.Load(), fallback.Load(), fake.calls.Load())
			}
			if tc.upstream == 0 && strings.Contains(w.Body.String(), "visible") {
				t.Fatal("business data on failure")
			}
		})
	}
}
