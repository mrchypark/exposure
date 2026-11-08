package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

type streamTestPDP struct {
	pdppb.UnimplementedPolicyDecisionPointServer
	t     *testing.T
	auth  string
	mode  string
	calls atomic.Int64
}

func (p *streamTestPDP) BatchCheckProviderUser(ctx context.Context, in *pdppb.ProviderUserBatchRequest) (*pdppb.DecisionResponse, error) {
	n := p.calls.Add(1)
	md, _ := metadata.FromIncomingContext(ctx)
	if in.ProviderId != "provider" || string(in.ChecksJson) != `{"checks":[{"action":"read","resource":{"id":"page1","provider":"provider","type":"page"}}]}` ||
		!reflect.DeepEqual(md.Get("authorization"), []string{p.auth}) || !reflect.DeepEqual(md.Get("x-organization-id"), []string{"org"}) ||
		!reflect.DeepEqual(md.Get("x-grant-app-auth-key"), []string{"test"}) {
		p.t.Error("incorrect decision input or metadata")
	}
	if p.mode == "unimplemented" {
		return nil, status.Error(codes.Unimplemented, "fixture")
	}
	if p.mode == "unavailable" && n == 3 {
		return nil, status.Error(codes.Unavailable, "fixture")
	}
	allowed := !(p.mode == "deny-first" && n == 1 || p.mode == "deny-last" && n == 3)
	revision := int64(7)
	if p.mode == "revision" && n == 3 {
		revision++
	}
	if p.mode == "malformed" && n == 1 {
		return &pdppb.DecisionResponse{DecisionJson: []byte(`{"results":[],"pepPolicyRevision":7}`)}, nil
	}
	if p.mode == "alias-deny-first" && n == 1 {
		return &pdppb.DecisionResponse{DecisionJson: []byte(`{"results":[{"allowed":false,"Allowed":true,"reason":"fixture"}],"pepPolicyRevision":7}`)}, nil
	}
	if p.mode == "alias-allow-first" && n == 1 {
		return &pdppb.DecisionResponse{DecisionJson: []byte(`{"results":[{"Allowed":true,"allowed":false,"reason":"fixture"}],"pepPolicyRevision":7}`)}, nil
	}
	if p.mode == "alias-revision" && n == 1 {
		return &pdppb.DecisionResponse{DecisionJson: []byte(`{"results":[{"allowed":true,"reason":"fixture"}],"PepPolicyRevision":7}`)}, nil
	}
	if p.mode == "conflicting-revision" && n == 1 {
		return &pdppb.DecisionResponse{DecisionJson: []byte(`{"results":[{"allowed":true,"reason":"fixture"}],"pepPolicyRevision":7,"PepPolicyRevision":8}`)}, nil
	}
	if p.mode == "null-allowed" && n == 1 {
		return &pdppb.DecisionResponse{DecisionJson: []byte(`{"results":[{"allowed":null,"reason":"fixture"}],"pepPolicyRevision":7}`)}, nil
	}
	b, _ := json.Marshal(map[string]any{"results": []any{map[string]any{"allowed": allowed, "reason": "fixture"}}, "pepPolicyRevision": revision})
	return &pdppb.DecisionResponse{DecisionJson: b}, nil
}

func TestStreamPilotPerFrameAuthorization(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		wantFrames  int
		wantChecks  int64
		wantCalls   int64
		wantSuccess bool
	}{
		{"allow", 2, 3, 1, true},
		{"deny-first", 0, 1, 0, false},
		{"deny-last", 1, 3, 1, false},
		{"revision", 1, 3, 1, false},
		{"unavailable", 1, 3, 1, false},
		{"upstream-error", 1, 2, 1, false},
		{"unimplemented", 0, 1, 0, false},
		{"malformed", 0, 1, 0, false},
		{"alias-deny-first", 0, 1, 0, false},
		{"alias-allow-first", 0, 1, 0, false},
		{"alias-revision", 0, 1, 0, false},
		{"conflicting-revision", 0, 1, 0, false},
		{"null-allowed", 0, 1, 0, false},
		{"wrong-scope", 0, 0, 0, false},
		{"wrong-org", 0, 0, 0, false},
		{"duplicate", 0, 0, 0, false},
		{"extra-metadata", 0, 0, 0, false},
		{"no-half-close", 0, 0, 0, false},
		{"two-requests", 0, 0, 0, false},
		{"wrong-method", 0, 0, 0, false},
		{"empty-stream", 0, 1, 1, false},
		{"max-content", 5, 6, 1, true},
		{"wire-cap-exceeded", 5, 6, 1, false},
		{"frame-cap-exceeded", 1, 2, 1, false},
		{"request-cap-exceeded", 0, 0, 0, false},
		{"client-cancel", 1, 2, 1, false},
		{"upstream-stall", 0, 1, 1, false},
		{"backpressure", 0, 0, 0, false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			desc := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("sample.proto"), Package: proto.String("sample"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request")}, {Name: proto.String("Response")}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Read"), InputType: proto.String(".sample.Request"), OutputType: proto.String(".sample.Response"), ServerStreaming: proto.Bool(true)}}}}}}}
			rawDesc, err := proto.Marshal(desc)
			if err != nil {
				t.Fatal(err)
			}
			auth := "Bearer " + goauthyJWT(t, `{"iss":"https://issuer.example","sub":"user","aud":["client","audience"],"azp":"client"}`)
			pdpListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			pdp := grpc.NewServer()
			checker := &streamTestPDP{t: t, auth: auth, mode: tc.mode}
			pdppb.RegisterPolicyDecisionPointServer(pdp, checker)
			go pdp.Serve(pdpListener)
			t.Cleanup(func() { pdp.Stop(); pdpListener.Close() })
			p := &Proxy{cfg: config.ProxyConfig{CredentialMode: "goauthy", GoauthyIssuer: "https://issuer.example", GoauthyUserClientID: "client", GoauthyUserResourceAudience: "audience", ProviderID: "provider", AppAuthKey: "test"}}
			if err := p.ConfigureGRPCLearner(pdpListener.Addr().String(), "", "", 2*time.Second); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { p.CloseGRPCLearner() })
			upListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var upstreamCalls atomic.Int64
			canceled := make(chan struct{}, 1)
			up := grpc.NewServer(grpc.ForceServerCodec(rawRPCCodec{}), grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
				upstreamCalls.Add(1)
				if tc.mode == "deny-last" || tc.mode == "revision" || tc.mode == "unavailable" || tc.mode == "client-cancel" || tc.mode == "upstream-stall" || tc.mode == "backpressure" {
					defer func() {
						<-stream.Context().Done()
						canceled <- struct{}{}
					}()
				}
				md, _ := metadata.FromIncomingContext(stream.Context())
				if len(md.Get("authorization")) != 0 || len(md.Get("x-organization-id")) != 0 || len(md.Get("x-grant-app-auth-key")) != 0 ||
					!reflect.DeepEqual(md.Get("x-scope"), []string{"workspace"}) || !reflect.DeepEqual(md.Get("x-page"), []string{"page1"}) ||
					!reflect.DeepEqual(md.Get("x-version"), []string{"v1"}) {
					t.Error("unexpected upstream metadata")
				}
				var b []byte
				if err := stream.RecvMsg(&b); err != nil {
					return err
				}
				if string(b) != "request" {
					t.Error("request bytes changed")
				}
				if tc.mode == "empty-stream" {
					return nil
				}
				if tc.mode == "upstream-stall" {
					<-stream.Context().Done()
					return nil
				}
				if tc.mode == "backpressure" {
					frame := bytes.Repeat([]byte("x"), 64<<10)
					for i := 0; i < 20; i++ {
						if err := stream.SendMsg(&frame); err != nil {
							return err
						}
					}
					<-stream.Context().Done()
					return nil
				}
				framesToSend := [][]byte{[]byte("header"), []byte("data")}
				if tc.mode == "client-cancel" {
					framesToSend = framesToSend[:1]
				}
				if tc.mode == "max-content" || tc.mode == "wire-cap-exceeded" {
					framesToSend = [][]byte{[]byte("header")}
					dataFrame := append([]byte{0x12, 0x80, 0x80, 0x04}, bytes.Repeat([]byte("x"), 64<<10)...)
					for i := 0; i < 4; i++ {
						framesToSend = append(framesToSend, dataFrame)
					}
					if tc.mode == "wire-cap-exceeded" {
						framesToSend = append(framesToSend, bytes.Repeat([]byte("y"), streamResponseWireMax-4*len(dataFrame)-len("header")+1))
					}
				}
				if tc.mode == "frame-cap-exceeded" {
					framesToSend = [][]byte{[]byte("header"), bytes.Repeat([]byte("z"), streamFrameWireMax+1)}
				}
				for i, frame := range framesToSend {
					if err := stream.SendMsg(&frame); err != nil {
						return err
					}
					if tc.mode == "upstream-error" && i == 0 {
						return status.Error(codes.Unavailable, "fixture")
					}
				}
				if tc.mode == "deny-last" || tc.mode == "revision" || tc.mode == "unavailable" || tc.mode == "client-cancel" {
					<-stream.Context().Done()
				}
				return nil
			}))
			go up.Serve(upListener)
			t.Cleanup(func() { up.Stop(); upListener.Close() })
			relay, err := newStreamPilot(p, upListener.Addr().String(), "/sample.Service/Read", rawDesc, shaBytes(rawDesc), "provider", "org", "read", "page", "x-page", []string{"x-scope", "x-page", "x-version"}, map[string]string{"x-scope": "workspace"}, streamResponseWireMax)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { relay.upstream.Close() })
			relayListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := relay.server()
			go server.Serve(relayListener)
			t.Cleanup(func() { server.Stop(); relayListener.Close() })
			client, err := grpc.NewClient("passthrough:///"+relayListener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry(), grpc.WithInitialWindowSize(65536), grpc.WithInitialConnWindowSize(65536))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			timeout := 2 * time.Second
			if tc.mode == "backpressure" {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			scope := "workspace"
			if tc.mode == "wrong-scope" {
				scope = "other"
			}
			md := metadata.Pairs("authorization", auth, "x-organization-id", "org", "x-scope", scope, "x-page", "page1", "x-version", "v1")
			if tc.mode == "wrong-org" {
				md.Set("x-organization-id", "other")
			}
			if tc.mode == "duplicate" {
				md.Append("x-page", "other")
			}
			if tc.mode == "extra-metadata" {
				md.Set("x-extra", "bad")
			}
			ctx = metadata.NewOutgoingContext(ctx, md)
			method := "/sample.Service/Read"
			if tc.mode == "wrong-method" {
				method = "/sample.Service/Other"
			}
			stream, err := client.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: tc.mode == "two-requests"}, method, grpc.ForceCodec(rawRPCCodec{}))
			if err != nil {
				t.Fatal(err)
			}
			request := []byte("request")
			if tc.mode == "request-cap-exceeded" {
				request = bytes.Repeat([]byte("a"), streamRequestMax+1)
			}
			if err := stream.SendMsg(&request); err != nil && tc.mode != "request-cap-exceeded" && tc.mode != "wrong-method" {
				t.Fatal(err)
			}
			if tc.mode == "two-requests" {
				if err := stream.SendMsg(&request); err != nil {
					t.Fatal(err)
				}
			}
			if tc.mode != "no-half-close" {
				if err := stream.CloseSend(); err != nil && tc.mode != "request-cap-exceeded" && tc.mode != "wrong-method" {
					t.Fatal(err)
				}
			}
			if tc.mode == "backpressure" {
				select {
				case <-canceled:
					t.Fatal("stream ended before testing flow control")
				case <-time.After(200 * time.Millisecond):
					if len(relay.sem) != 1 || checker.calls.Load() < 2 {
						t.Fatal("relay did not remain active while client stalled")
					}
				}
				<-ctx.Done()
				select {
				case <-canceled:
				case <-time.After(time.Second):
					t.Fatal("stalled upstream was not canceled")
				}
				deadline := time.Now().Add(time.Second)
				for len(relay.sem) != 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if len(relay.sem) != 0 {
					t.Fatal("stalled relay retained its concurrency slot")
				}
				return
			}
			frames := 0
			for {
				var b []byte
				err = stream.RecvMsg(&b)
				if err != nil {
					break
				}
				if tc.mode == "max-content" || tc.mode == "wire-cap-exceeded" {
					dataFrame := append([]byte{0x12, 0x80, 0x80, 0x04}, bytes.Repeat([]byte("x"), 64<<10)...)
					if frames == 0 && string(b) != "header" || frames > 0 && (frames > 4 || !bytes.Equal(b, dataFrame)) {
						t.Fatal("response bytes or order changed")
					}
				} else if frames > 1 || string(b) != []string{"header", "data"}[frames] {
					t.Fatal("response bytes or order changed")
				}
				frames++
				if tc.mode == "client-cancel" {
					cancel()
				}
			}
			if (err == io.EOF) != tc.wantSuccess || frames != tc.wantFrames || checker.calls.Load() != tc.wantChecks || upstreamCalls.Load() != tc.wantCalls {
				t.Fatalf("err=%v frames=%d checks=%d calls=%d", err, frames, checker.calls.Load(), upstreamCalls.Load())
			}
			if tc.mode == "deny-last" || tc.mode == "revision" || tc.mode == "unavailable" || tc.mode == "client-cancel" || tc.mode == "upstream-stall" {
				select {
				case <-canceled:
				case <-time.After(time.Second):
					t.Fatal("upstream was not canceled")
				}
			}
		})
	}
}
