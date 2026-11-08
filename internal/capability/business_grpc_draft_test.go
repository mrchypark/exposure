package capability

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

type businessTestPDP struct {
	pdppb.UnimplementedPolicyDecisionPointServer
	catalog       []byte
	mode          string
	t             *testing.T
	expected      map[string]any
	authorization string
	catalogCalls  atomic.Int64
	decisionCalls atomic.Int64
}

func (p *businessTestPDP) GetGrpcCatalog(context.Context, *pdppb.CatalogRequest) (*pdppb.CatalogResponse, error) {
	p.catalogCalls.Add(1)
	return &pdppb.CatalogResponse{CatalogJson: p.catalog}, nil
}
func (p *businessTestPDP) DecideGrpc(ctx context.Context, in *pdppb.DecisionRequest) (*pdppb.DecisionResponse, error) {
	p.decisionCalls.Add(1)
	md, _ := metadata.FromIncomingContext(ctx)
	if !reflect.DeepEqual(md.Get("authorization"), []string{p.authorization}) || !reflect.DeepEqual(md.Get("x-grant-app-auth-key"), []string{"test"}) || !reflect.DeepEqual(md.Get("x-organization-id"), []string{"org"}) {
		p.t.Error("unexpected learner metadata")
	}
	var fields map[string]any
	if err := json.Unmarshal(in.EvidenceJson, &fields); err != nil {
		return nil, err
	}
	binding, ok := fields["requestBinding"].(string)
	if !ok || !regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`).MatchString(binding) {
		p.t.Error("invalid binding")
	}
	delete(fields, "requestBinding")
	if !reflect.DeepEqual(fields, p.expected) {
		p.t.Errorf("evidence mismatch: got %v want %v", fields, p.expected)
	}
	fields["requestBinding"] = binding
	now := time.Now().UTC()
	fields["allowed"] = p.mode != "deny"
	fields["reason"] = "fixture"
	fields["actionId"] = "read"
	fields["organizationId"] = "org"
	fields["principalDigest"] = strings.Repeat("1", 64)
	fields["issuedAt"] = now.Format(time.RFC3339Nano)
	fields["expiresAt"] = now.Add(time.Second).Format(time.RFC3339Nano)
	if p.mode == "tamper" {
		fields["messageDigest"] = shaBytes([]byte("wrong"))
	}
	if p.mode == "expired" {
		fields["expiresAt"] = now.Add(-time.Second).Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(fields)
	return &pdppb.DecisionResponse{DecisionJson: b}, err
}

func TestBusinessDraftUnaryForwarding(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		wantCalls   int64
		wantSuccess bool
	}{{"allow", 1, true}, {"advertisement", 1, true}, {"deny", 0, false}, {"tamper", 0, false}, {"expired", 0, false}, {"metadata", 0, false}, {"duplicate", 0, false}, {"compression", 0, false}, {"upstream", 1, false}, {"longdeadline", 0, false}, {"nodeadline", 0, false}, {"nohalfclose", 0, false}, {"oversize", 0, false}, {"twomessages", 0, false}} {
		t.Run(tc.mode, func(t *testing.T) {
			desc := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("fixture.proto"), Package: proto.String("fixture"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request")}, {Name: proto.String("Response")}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Get"), InputType: proto.String(".fixture.Request"), OutputType: proto.String(".fixture.Response")}}}}}}}
			descBytes, err := proto.Marshal(desc)
			if err != nil {
				t.Fatal(err)
			}
			cap := businessCapability{CapabilityID: "cap", Version: 1, Enabled: true, FullMethod: "/fixture.Service/Get", DescriptorDigest: shaBytes(descBytes), ActionID: "read", ResourceType: "object", ResourceID: "fixed", MaxMessageBytes: 1024}
			cap.ContractDigest, _ = businessCapabilityDigest(cap)
			now := time.Now().UTC()
			cat := businessCatalog{SchemaVersion: 1, ProviderID: "provider", Generation: 1, Capabilities: []businessCapability{cap}, PepClientID: "pep", AuthorizationMode: "user", PepPolicyRevision: 7, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(25 * time.Second).Format(time.RFC3339Nano)}
			cat.CatalogDigest, _ = businessCatalogDigest(cat)
			catalogBytes, _ := json.Marshal(cat)
			authorization := "Bearer " + goauthyJWT(t, `{"sub":"user","aud":"audience"}`)
			preimage := append([]byte("grant.http-capability.provider-credential.v1"), make([]byte, 8)...)
			binary.BigEndian.PutUint64(preimage[len(preimage)-8:], uint64(len(authorization)))
			credentialHash := sha256.Sum256(append(preimage, []byte(authorization)...))
			expected := map[string]any{"wireVersion": float64(1), "providerId": "provider", "pepClientId": "pep", "pepPolicyRevision": float64(7), "catalogGeneration": float64(1), "catalogDigest": cat.CatalogDigest, "capabilityId": "cap", "capabilityVersion": float64(1), "contractDigest": cap.ContractDigest, "fullMethod": "/fixture.Service/Get", "descriptorDigest": cap.DescriptorDigest, "rpcKind": "unary", "resourceType": "object", "resourceId": "fixed", "messageDigest": "sha256:fbc601aefa01f8692f1ee4ca767d28f0ee54083d0bbee08bcee1f2bb3b75e3b7", "messageLength": float64(3), "forwardedMetadataDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "providerCredentialDigest": "sha256:" + hex.EncodeToString(credentialHash[:]), "providerCredential": map[string]any{"subject": "goauthy:https://issuer.example/user", "audience": "audience"}}
			pdpListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			pdp := grpc.NewServer()
			fixturePDP := &businessTestPDP{catalog: catalogBytes, mode: tc.mode, t: t, expected: expected, authorization: authorization}
			pdppb.RegisterPolicyDecisionPointServer(pdp, fixturePDP)
			go pdp.Serve(pdpListener)
			t.Cleanup(func() { pdp.Stop(); pdpListener.Close() })
			p := &Proxy{cfg: config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://issuer.example", ProviderID: "provider", PepClientID: "pep", AppAuthKey: "test"}}
			if err := p.ConfigureGRPCLearner(pdpListener.Addr().String(), "", "", 2*time.Second); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { p.CloseGRPCLearner() })
			var calls atomic.Int64
			upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			upstream := grpc.NewServer(grpc.ForceServerCodec(rawRPCCodec{}), grpc.UnknownServiceHandler(func(_ any, s grpc.ServerStream) error {
				incoming, _ := metadata.FromIncomingContext(s.Context())
				if len(incoming.Get("authorization")) != 0 || len(incoming.Get("x-grant-app-auth-key")) != 0 || len(incoming.Get("x-organization-id")) != 0 {
					t.Error("credentials forwarded")
				}
				if strings.Contains(strings.Join(incoming.Get("grpc-accept-encoding"), ","), "untrusted-fixture") {
					t.Error("client advertisement forwarded")
				}
				var b []byte
				if err := s.RecvMsg(&b); err != nil {
					return err
				}
				calls.Add(1)
				if tc.mode == "upstream" {
					return status.Error(codes.Unavailable, "fixture")
				}
				if string(b) != string([]byte{0x0a, 0x01, 0x78}) {
					t.Error("bytes changed")
				}
				return s.SendMsg(&b)
			}))
			go upstream.Serve(upstreamListener)
			t.Cleanup(func() { upstream.Stop(); upstreamListener.Close() })
			d, err := newBusinessDraft(p, upstreamListener.Addr().String(), map[string][]byte{cap.DescriptorDigest: descBytes}, map[string]businessCapability{cap.FullMethod: cap}, cat.CatalogDigest, 1024)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { d.upstream.Close() })
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server, err := d.newServer()
			if err != nil {
				t.Fatal(err)
			}
			go server.Serve(listener)
			t.Cleanup(func() { server.Stop(); listener.Close() })
			client, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry(), grpc.WithDisableServiceConfig())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			timeout := time.Second
			if tc.mode == "longdeadline" {
				timeout = 10 * time.Second
			}
			if tc.mode == "nohalfclose" {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if tc.mode == "nodeadline" {
				cancel()
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(context.Background())
				timer := time.AfterFunc(2*time.Second, stop)
				defer func() { timer.Stop(); stop() }()
			}
			values := metadata.Pairs("authorization", authorization, "x-organization-id", "org")
			if tc.mode == "metadata" {
				values.Set("x-arbitrary", "value")
			}
			if tc.mode == "duplicate" {
				values.Append("authorization", "Bearer other")
			}
			if tc.mode == "advertisement" {
				values.Append("grpc-accept-encoding", "untrusted-fixture")
			}
			ctx = metadata.NewOutgoingContext(ctx, values)
			request := []byte{0x0a, 0x01, 0x78}
			if tc.mode == "oversize" {
				request = make([]byte, 1025)
			}
			var response []byte
			options := []grpc.CallOption{grpc.ForceCodec(rawRPCCodec{})}
			if tc.mode == "compression" {
				options = append(options, grpc.UseCompressor("gzip"))
			}
			if tc.mode == "nohalfclose" || tc.mode == "twomessages" {
				stream, streamErr := client.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, cap.FullMethod, options...)
				if streamErr != nil {
					t.Fatal(streamErr)
				}
				if streamErr = stream.SendMsg(&request); streamErr != nil {
					t.Fatal(streamErr)
				}
				if tc.mode == "twomessages" {
					if err := stream.SendMsg(&request); err != nil {
						t.Fatal(err)
					}
					if err := stream.CloseSend(); err != nil {
						t.Fatal(err)
					}
				}
				err = stream.RecvMsg(&response)
			} else {
				err = client.Invoke(ctx, cap.FullMethod, &request, &response, options...)
			}
			if (err == nil) != tc.wantSuccess || calls.Load() != tc.wantCalls {
				t.Fatalf("err=%v calls=%d", err, calls.Load())
			}
			if tc.mode == "nohalfclose" && (status.Code(err) != codes.DeadlineExceeded || fixturePDP.catalogCalls.Load() != 1 || fixturePDP.decisionCalls.Load() != 0) {
				t.Fatalf("unbounded half-close: error=%v catalog=%d decisions=%d", err, fixturePDP.catalogCalls.Load(), fixturePDP.decisionCalls.Load())
			}
			if tc.wantSuccess && string(response) != string(request) {
				t.Fatal("response changed")
			}
		})
	}
}
