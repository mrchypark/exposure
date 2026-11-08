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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type userPDP struct {
	pdppb.UnimplementedPolicyDecisionPointServer
	t                   *testing.T
	mode                string
	catalogJSON         []byte
	catalogs, decisions atomic.Int64
}

func (s *userPDP) GetHttpCatalog(ctx context.Context, req *pdppb.CatalogRequest) (*pdppb.CatalogResponse, error) {
	s.catalogs.Add(1)
	md, _ := metadata.FromIncomingContext(ctx)
	if req.ProviderId != "independent-identity" || len(md.Get("x-grant-app-auth-key")) != 1 || md.Get("x-grant-app-auth-key")[0] != "fixture-key" {
		s.t.Error("catalog binding changed")
	}
	return &pdppb.CatalogResponse{CatalogJson: s.catalogJSON}, nil
}

func (s *userPDP) DecideHttp(ctx context.Context, req *pdppb.DecisionRequest) (*pdppb.DecisionResponse, error) {
	s.decisions.Add(1)
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md.Get("authorization")) != 1 || len(md.Get("x-organization-id")) != 1 || md.Get("x-organization-id")[0] != "fixture-org" || len(md.Get("x-grant-app-auth-key")) != 1 || md.Get("x-grant-app-auth-key")[0] != "fixture-key" {
		s.t.Error("decision metadata changed")
	}
	var in map[string]any
	if err := json.Unmarshal(req.EvidenceJson, &in); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid evidence")
	}
	if in["wireVersion"] != float64(2) || in["pepPolicyRevision"] != float64(7) {
		s.t.Error("USER wire version or revision changed")
	}
	allow := true
	w := httptest.NewRecorder()
	echoDecisionMap(s.t, &allow, in, "self", "identity.enroll")(w, httptest.NewRequest(http.MethodPost, "/", nil))
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		return nil, status.Error(codes.Internal, "invalid fixture")
	}
	out["wireVersion"], out["pepPolicyRevision"] = 2, 7
	if s.mode == "wrong-version" {
		out["wireVersion"] = 1
	}
	if s.mode == "wrong-revision" {
		out["pepPolicyRevision"] = 8
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal")
	}
	return &pdppb.DecisionResponse{DecisionJson: b}, nil
}

func TestGRPCRefreshAndUserDecisionBinding(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		status   int
		upstream int64
	}{{"allow", 200, 1}, {"wrong-version", 502, 0}, {"wrong-revision", 502, 0}} {
		t.Run(tc.mode, func(t *testing.T) {
			cat := organizationPolicyCatalog(organizationPolicyCapability("required"))
			cat.AuthorizationMode, cat.PepPolicyRevision = "user", 7
			b, err := json.Marshal(cat)
			if err != nil {
				t.Fatal(err)
			}
			fake := &userPDP{t: t, mode: tc.mode, catalogJSON: b}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer()
			pdppb.RegisterPolicyDecisionPointServer(server, fake)
			go server.Serve(listener)
			defer server.Stop()
			var upstream, fallback atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/v2/http-capabilities/") {
					fallback.Add(1)
					http.Error(w, "fallback", 500)
					return
				}
				upstream.Add(1)
				_, _ = w.Write([]byte(`{"visible":true}`))
			}))
			defer origin.Close()
			cfg := config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://issuer.example", ProviderID: cat.ProviderID, PepClientID: cat.PepClientID, AppAuthKey: "fixture-key", Origin: origin.URL, ExpectedCatalogDigest: cat.CatalogDigest, AuthorizationMode: "forward-user", MaxRequestBytes: 1024, MaxResponseBytes: 1024}
			p, err := New(cfg, origin.URL, origin.Client(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.ConfigureGRPCLearner(listener.Addr().String(), "", "", time.Second); err != nil {
				t.Fatal(err)
			}
			defer p.CloseGRPCLearner()
			if err := p.Refresh(context.Background()); err != nil {
				t.Fatalf("gRPC catalog rejected: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/accounts/enroll", nil)
			req.Header.Set("Authorization", "Bearer "+goauthyJWT(t, `{"sub":"fixture-user","aud":"resource"}`))
			req.Header.Set("X-Organization-ID", "fixture-org")
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, req)
			if w.Code != tc.status || upstream.Load() != tc.upstream || fallback.Load() != 0 || fake.catalogs.Load() != 1 || fake.decisions.Load() != 1 {
				t.Fatalf("status=%d upstream=%d fallback=%d catalog=%d decisions=%d", w.Code, upstream.Load(), fallback.Load(), fake.catalogs.Load(), fake.decisions.Load())
			}
			if tc.upstream == 0 && strings.Contains(w.Body.String(), "visible") {
				t.Fatal("business bytes on denial")
			}
		})
	}
}
