package capability

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type trustedGRPCStub struct {
	pdppb.UnimplementedPolicyDecisionPointServer
	catalogJSON []byte
	onDecide    func(ctx context.Context, in map[string]any) map[string]any
}

func (s *trustedGRPCStub) GetHttpCatalog(ctx context.Context, _ *pdppb.CatalogRequest) (*pdppb.CatalogResponse, error) {
	return &pdppb.CatalogResponse{CatalogJson: s.catalogJSON}, nil
}

func (s *trustedGRPCStub) DecideHttp(ctx context.Context, req *pdppb.DecisionRequest) (*pdppb.DecisionResponse, error) {
	var in map[string]any
	if err := json.Unmarshal(req.GetEvidenceJson(), &in); err != nil {
		return nil, err
	}
	out := s.onDecide(ctx, in)
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return &pdppb.DecisionResponse{DecisionJson: b}, nil
}

func TestTrustedCredentialModeHTTP(t *testing.T) {
	const gatewayKey = "gw-secret-key"
	const path = "/api/v1/admin/providers/fixture-provider/http-capability-active"
	const organization = "fixture-org"

	for _, tc := range []struct {
		name              string
		authMode          string
		upstreamToken     string
		catalogUserMode   bool
		reqHeaders        map[string]string
		wantStatus        int
		wantDecideCalls   int64
		wantUpstreamCalls int64
	}{
		{
			name:              "valid trusted forward-user",
			authMode:          "forward-user",
			reqHeaders:        map[string]string{"X-Grant-Gateway-Key": gatewayKey, "X-Operable-Subject": "user-123", "X-Organization-ID": organization},
			wantStatus:        http.StatusOK,
			wantDecideCalls:   1,
			wantUpstreamCalls: 1,
		},
		{
			name:              "valid trusted forward-user with user catalog mode and incoming bearer ignored by decide",
			authMode:          "forward-user",
			catalogUserMode:   true,
			reqHeaders:        map[string]string{"X-Grant-Gateway-Key": gatewayKey, "X-Operable-Subject": "user-123", "X-Organization-ID": organization, "Authorization": "Bearer upstream-token"},
			wantStatus:        http.StatusOK,
			wantDecideCalls:   1,
			wantUpstreamCalls: 1,
		},
		{
			name:              "valid trusted service-token",
			authMode:          "service-token",
			upstreamToken:     "svc-secret",
			reqHeaders:        map[string]string{"X-Grant-Gateway-Key": gatewayKey, "X-Operable-Subject": "user-123", "X-Organization-ID": organization},
			wantStatus:        http.StatusOK,
			wantDecideCalls:   1,
			wantUpstreamCalls: 1,
		},
		{
			name:       "missing gateway key",
			authMode:   "forward-user",
			reqHeaders: map[string]string{"X-Operable-Subject": "user-123", "X-Organization-ID": organization},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong gateway key",
			authMode:   "forward-user",
			reqHeaders: map[string]string{"X-Grant-Gateway-Key": "wrong", "X-Operable-Subject": "user-123", "X-Organization-ID": organization},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing subject",
			authMode:   "forward-user",
			reqHeaders: map[string]string{"X-Grant-Gateway-Key": gatewayKey, "X-Organization-ID": organization},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "blank subject",
			authMode:   "forward-user",
			reqHeaders: map[string]string{"X-Grant-Gateway-Key": gatewayKey, "X-Operable-Subject": "   ", "X-Organization-ID": organization},
			wantStatus: http.StatusUnauthorized,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cap := organizationPolicyCapability("required")
			cap.Method = http.MethodGet
			cap.PathTemplate = "/api/v1/admin/providers/{provider}/http-capability-active"
			cap.CapabilityID = "management.catalog.read"
			action := "grant.http.catalog.read"
			cap.ActionID = &action
			cap.Resource = &resource{Type: "provider", ID: extractor{Kind: "pathSegment", Name: "provider", Format: "asciiToken"}}
			if tc.authMode == "service-token" {
				cap.Request.Authorization = "service-token"
			}
			cap.ContractDigest = capabilityDigest(cap)

			cat := organizationPolicyCatalog(cap)
			cat.Generation = 177
			if tc.catalogUserMode {
				cat.AuthorizationMode = "user"
				cat.PepPolicyRevision = 1
			}
			cat.CatalogDigest = catalogDigest(cat)

			var decideCalls, upstreamCalls atomic.Int64
			grant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v2/http-capabilities/catalog/" + cat.ProviderID:
					_ = json.NewEncoder(w).Encode(cat)
				case "/api/v2/http-capabilities/decide":
					decideCalls.Add(1)
					if r.Header.Get("Authorization") != "" {
						t.Errorf("trusted decide must not forward Authorization header, got %q", r.Header.Get("Authorization"))
					}
					if r.Header.Get("X-Grant-Gateway-Key") != gatewayKey {
						t.Errorf("unexpected X-Grant-Gateway-Key: %q", r.Header.Get("X-Grant-Gateway-Key"))
					}
					if r.Header.Get("X-Grant-Subject") != "user-123" {
						t.Errorf("unexpected X-Grant-Subject: %q", r.Header.Get("X-Grant-Subject"))
					}
					if r.Header.Get("X-Grant-Client-ID") != "operable" {
						t.Errorf("unexpected X-Grant-Client-ID: %q", r.Header.Get("X-Grant-Client-ID"))
					}
					var in map[string]any
					if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
						t.Fatal(err)
					}
					cred, _ := in["providerCredential"].(map[string]any)
					if cred["subject"] != "user-123" || cred["audience"] != "https://operable.dev.conalog.com/grant" {
						t.Errorf("unexpected providerCredential: %#v", cred)
					}
					if in["providerCredentialDigest"] != credentialDigest("") {
						t.Errorf("unexpected providerCredentialDigest: %v", in["providerCredentialDigest"])
					}
					now := time.Now().UTC()
					out := map[string]any{
						"allowed":                  true,
						"reason":                   "trusted_gateway",
						"providerId":               in["providerId"],
						"pepClientId":              in["pepClientId"],
						"catalogGeneration":        in["catalogGeneration"],
						"catalogDigest":            in["catalogDigest"],
						"capabilityId":             in["capabilityId"],
						"capabilityVersion":        in["capabilityVersion"],
						"contractDigest":           in["contractDigest"],
						"actionId":                 action,
						"resourceType":             in["resourceType"],
						"resourceId":               in["resourceId"],
						"method":                   in["method"],
						"canonicalPath":            in["canonicalPath"],
						"canonicalQueryDigest":     in["canonicalQueryDigest"],
						"forwardedHeaderDigest":    in["forwardedHeaderDigest"],
						"bodyDigest":               in["bodyDigest"],
						"bodyLength":               in["bodyLength"],
						"providerCredentialDigest": in["providerCredentialDigest"],
						"providerSubject":          cred["subject"],
						"providerAudience":         cred["audience"],
						"requestBinding":           in["requestBinding"],
						"principalDigest":          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						"issuedAt":                 now.Format(time.RFC3339Nano),
						"expiresAt":                now.Add(5 * time.Second).Format(time.RFC3339Nano),
					}
					if tc.catalogUserMode {
						out["wireVersion"] = 2
						out["pepPolicyRevision"] = 1
					}
					_ = json.NewEncoder(w).Encode(out)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer grant.Close()

			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				if r.Header.Get("X-Grant-Gateway-Key") != "" || r.Header.Get("X-Grant-Subject") != "" {
					t.Errorf("gateway headers leaked to upstream: key=%q subj=%q", r.Header.Get("X-Grant-Gateway-Key"), r.Header.Get("X-Grant-Subject"))
				}
				if tc.authMode == "service-token" {
					if r.Header.Get("Authorization") != tc.upstreamToken {
						t.Errorf("expected service token, got %q", r.Header.Get("Authorization"))
					}
					if r.Header.Get("X-Operable-Subject") != "" {
						t.Errorf("subject header leaked in service-token mode: %q", r.Header.Get("X-Operable-Subject"))
					}
				} else if r.Header.Get("X-Operable-Subject") != "user-123" {
					t.Errorf("expected X-Operable-Subject=user-123, got %q", r.Header.Get("X-Operable-Subject"))
				}
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer upstream.Close()

			cfg := config.ProxyConfig{
				AuthorizationMode:     tc.authMode,
				UpstreamToken:         tc.upstreamToken,
				ProviderID:            cat.ProviderID,
				PepClientID:           cat.PepClientID,
				Origin:                upstream.URL,
				ExpectedCatalogDigest: cat.CatalogDigest,
				AppAuthKey:            "app-key",
				CredentialMode:        "trusted",
				TrustedGatewayKey:     gatewayKey,
				TrustedAudience:       "https://operable.dev.conalog.com/grant",
				TrustedClientID:       "operable",
				MaxRequestBytes:       1 << 20,
				MaxResponseBytes:      1 << 20,
			}
			p, err := New(cfg, grant.URL, grant.Client(), 4)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, path, nil)
			for k, v := range tc.reqHeaders {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, r)
			if w.Code != tc.wantStatus || decideCalls.Load() != tc.wantDecideCalls || upstreamCalls.Load() != tc.wantUpstreamCalls {
				t.Fatalf("status=%d (want %d) decide=%d (want %d) upstream=%d (want %d) body=%s", w.Code, tc.wantStatus, decideCalls.Load(), tc.wantDecideCalls, upstreamCalls.Load(), tc.wantUpstreamCalls, w.Body.String())
			}
		})
	}
}

func TestTrustedCredentialModeGRPCAndPublicAuthnSpoofRejection(t *testing.T) {
	const gatewayKey = "gw-secret-key"
	capAuth := organizationPolicyCapability("required")
	capAuth.Method = http.MethodGet
	capAuth.PathTemplate = "/api/v1/admin/providers/{provider}/http-capability-active"
	capAuth.CapabilityID = "management.catalog.read"
	action := "grant.http.catalog.read"
	capAuth.ActionID = &action
	capAuth.Resource = &resource{Type: "provider", ID: extractor{Kind: "pathSegment", Name: "provider", Format: "asciiToken"}}
	capAuth.ContractDigest = capabilityDigest(capAuth)

	capPublic := capability{
		CapabilityID: "public.login",
		Version:      1,
		Enabled:      true,
		AccessMode:   "public_authn",
		Method:       http.MethodPost,
		PathTemplate: "/api/public/login",
		Resource:     &resource{Type: "session", ID: extractor{Kind: "fixed", Value: "login"}},
		Query:        queryPolicy{Mode: "none"},
		Request:      requestPolicy{Body: "none", ForwardHeaders: []string{"X-Operable-Subject"}},
		Response:     responsePolicy{MaxBytes: 1024, Redirects: "deny"},
	}
	capPublic.ContractDigest = capabilityDigest(capPublic)

	cat := organizationPolicyCatalog(capAuth)
	cat.Capabilities = append(cat.Capabilities, capPublic)
	cat.CatalogDigest = catalogDigest(cat)
	catBytes, _ := json.Marshal(cat)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := grpc.NewServer()
	pdppb.RegisterPolicyDecisionPointServer(srv, &trustedGRPCStub{
		catalogJSON: catBytes,
		onDecide: func(ctx context.Context, in map[string]any) map[string]any {
			md, ok := metadata.FromIncomingContext(ctx)
			first := func(k string) string {
				if vals := md.Get(k); len(vals) > 0 {
					return vals[0]
				}
				return ""
			}
			if !ok || first("x-grant-gateway-key") != gatewayKey || first("x-grant-subject") != "grpc-user" || first("x-grant-client-id") != "operable" || first("authorization") != "" {
				t.Errorf("unexpected gRPC metadata: %#v", md)
			}
			cred := in["providerCredential"].(map[string]any)
			now := time.Now().UTC()
			return map[string]any{
				"allowed":                  true,
				"reason":                   "trusted_gateway",
				"providerId":               in["providerId"],
				"pepClientId":              in["pepClientId"],
				"catalogGeneration":        in["catalogGeneration"],
				"catalogDigest":            in["catalogDigest"],
				"capabilityId":             in["capabilityId"],
				"capabilityVersion":        in["capabilityVersion"],
				"contractDigest":           in["contractDigest"],
				"actionId":                 action,
				"resourceType":             in["resourceType"],
				"resourceId":               in["resourceId"],
				"method":                   in["method"],
				"canonicalPath":            in["canonicalPath"],
				"canonicalQueryDigest":     in["canonicalQueryDigest"],
				"forwardedHeaderDigest":    in["forwardedHeaderDigest"],
				"bodyDigest":               in["bodyDigest"],
				"bodyLength":               in["bodyLength"],
				"providerCredentialDigest": in["providerCredentialDigest"],
				"providerSubject":          cred["subject"],
				"providerAudience":         cred["audience"],
				"requestBinding":           in["requestBinding"],
				"principalDigest":          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"issuedAt":                 now.Format(time.RFC3339Nano),
				"expiresAt":                now.Add(5 * time.Second).Format(time.RFC3339Nano),
			}
		},
	})
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Grant-Subject") != "grpc-user" {
			t.Errorf("expected custom subject header X-Grant-Subject=grpc-user, got %q", r.Header.Get("X-Grant-Subject"))
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	cfg := config.ProxyConfig{
		AuthorizationMode:         "forward-user",
		ProviderID:                cat.ProviderID,
		PepClientID:               cat.PepClientID,
		Origin:                    upstream.URL,
		ExpectedCatalogDigest:     cat.CatalogDigest,
		AppAuthKey:                "app-key",
		AuthnLimiterKey:           "limiter",
		CredentialMode:            "trusted",
		TrustedGatewayKey:         gatewayKey,
		TrustedSubjectHeader:      "X-Grant-Subject",
		TrustedAudience:           "https://operable.dev.conalog.com/grant",
		TrustedClientID:           "operable",
		MaxRequestBytes:           1 << 20,
		MaxResponseBytes:          1 << 20,
		PublicAuthnGlobalCapacity: 10,
		PublicAuthnPeerCapacity:   10,
		PublicAuthnGlobalRefill:   time.Second,
		PublicAuthnPeerRefill:     time.Second,
	}
	p, err := New(cfg, "", upstream.Client(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ConfigureGRPCLearner(ln.Addr().String(), "", "", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	defer p.CloseGRPCLearner()
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/providers/fixture-provider/http-capability-active", nil)
	r.Header.Set("X-Grant-Gateway-Key", gatewayKey)
	r.Header.Set("X-Grant-Subject", "grpc-user")
	r.Header.Set("X-Organization-ID", "org-1")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("gRPC trusted request failed: %d %s", w.Code, w.Body.String())
	}

	// Spoofed trusted headers on public_authn must be rejected.
	pub := httptest.NewRequest(http.MethodPost, "/api/public/login", nil)
	pub.RemoteAddr = "127.0.0.1:12345"
	pub.Header.Set("X-Grant-Gateway-Key", gatewayKey)
	pub.Header.Set("X-Grant-Subject", "spoofed")
	pubW := httptest.NewRecorder()
	p.Handler().ServeHTTP(pubW, pub)
	if pubW.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for spoofed trusted headers on public_authn, got %d %s", pubW.Code, pubW.Body.String())
	}
}
