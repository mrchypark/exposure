package capability

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type testPDP struct {
	pdppb.UnimplementedPolicyDecisionPointServer
	t            *testing.T
	decisionCode codes.Code
	oversized    bool
}

func (p *testPDP) GetHttpCatalog(ctx context.Context, in *pdppb.CatalogRequest) (*pdppb.CatalogResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if in.ProviderId != "provider" || len(md.Get("x-grant-app-auth-key")) != 1 || md.Get("x-grant-app-auth-key")[0] != "key" {
		p.t.Error("catalog binding mismatch")
	}
	if _, ok := ctx.Deadline(); !ok {
		p.t.Error("missing deadline")
	}
	return &pdppb.CatalogResponse{CatalogJson: []byte(`{"catalog":true}`)}, nil
}

func (p *testPDP) DecideHttp(ctx context.Context, in *pdppb.DecisionRequest) (*pdppb.DecisionResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if !bytes.Equal(in.EvidenceJson, []byte(`{"n":9007199254740993}`)) || len(md.Get("authorization")) != 1 || md.Get("authorization")[0] != "Bearer token" || len(md.Get("x-organization-id")) != 1 || md.Get("x-organization-id")[0] != "org" || len(md.Get("x-grant-app-auth-key")) != 1 || md.Get("x-grant-app-auth-key")[0] != "key" {
		p.t.Error("decision binding mismatch")
	}
	if p.decisionCode != codes.OK {
		return nil, status.Error(p.decisionCode, "rejected")
	}
	if p.oversized {
		return &pdppb.DecisionResponse{DecisionJson: make([]byte, (64<<10)+1)}, nil
	}
	return &pdppb.DecisionResponse{DecisionJson: []byte(`{"allowed":false}`)}, nil
}

func TestGRPCLearnerErrorMappingAndLimits(t *testing.T) {
	for _, tc := range []struct {
		name      string
		code      codes.Code
		oversized bool
		want      int
	}{
		{"unauthenticated", codes.Unauthenticated, false, 401},
		{"denied", codes.PermissionDenied, false, 403},
		{"unavailable", codes.Unavailable, false, 0},
		{"unknown", codes.Unknown, false, 0},
		{"oversized", codes.OK, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer()
			pdppb.RegisterPolicyDecisionPointServer(server, &testPDP{t: t, decisionCode: tc.code, oversized: tc.oversized})
			go server.Serve(listener)
			t.Cleanup(func() { server.Stop(); listener.Close() })
			p := &Proxy{}
			if err := p.ConfigureGRPCLearner(listener.Addr().String(), "", "", time.Second); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { p.CloseGRPCLearner() })
			_, code, err := p.learner.decide(context.Background(), []byte(`{"n":9007199254740993}`), "Bearer token", "org", "key")
			if err == nil || code != tc.want {
				t.Fatalf("got code %d error %v", code, err)
			}
		})
	}
}

func TestGRPCLearnerExactBytesAndMetadata(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	pdppb.RegisterPolicyDecisionPointServer(server, &testPDP{t: t})
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); listener.Close() })
	p := &Proxy{}
	if err := p.ConfigureGRPCLearner(listener.Addr().String(), "", "", time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.CloseGRPCLearner() })
	b, err := p.learner.catalog(context.Background(), "provider", "key")
	if err != nil || string(b) != `{"catalog":true}` {
		t.Fatalf("catalog: %s %v", b, err)
	}
	b, code, err := p.learner.decide(context.Background(), []byte(`{"n":9007199254740993}`), "Bearer token", "org", "key")
	if err != nil || code != 0 || string(b) != `{"allowed":false}` {
		t.Fatalf("decision: %s %d %v", b, code, err)
	}
	_, _, err = p.learner.decide(context.Background(), make([]byte, grpcPayloadLimit+1), "Bearer token", "org", "key")
	if err == nil {
		t.Fatal("oversized evidence accepted")
	}
}
