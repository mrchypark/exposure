package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type startupPDP struct {
	pdppb.UnimplementedPolicyDecisionPointServer
	catalog []byte
	checks  atomic.Int64
	allow   atomic.Bool
	t       *testing.T
	bearer  string
}

func (p *startupPDP) BatchCheckProviderUser(ctx context.Context, req *pdppb.ProviderUserBatchRequest) (*pdppb.DecisionResponse, error) {
	p.checks.Add(1)
	md, _ := metadata.FromIncomingContext(ctx)
	if req.ProviderId != "provider" || string(req.ChecksJson) != `{"checks":[{"action":"read","resource":{"id":"page1","provider":"provider","type":"page"}}]}` || len(md.Get("authorization")) != 1 || len(md.Get("x-organization-id")) != 1 || len(md.Get("x-grant-app-auth-key")) != 1 {
		p.t.Error("unexpected Grant tuple or credentials")
	} else if md.Get("authorization")[0] != p.bearer || md.Get("x-organization-id")[0] != "org" || md.Get("x-grant-app-auth-key")[0] != "fixture-key" {
		p.t.Error("unexpected Grant credential binding")
	}
	if p.allow.Load() {
		return &pdppb.DecisionResponse{DecisionJson: []byte(`{"results":[{"allowed":true,"reason":"allow"}],"pepPolicyRevision":1}`)}, nil
	}
	return nil, status.Error(codes.Unimplemented, "fixture")
}

func (p *startupPDP) GetHttpCatalog(context.Context, *pdppb.CatalogRequest) (*pdppb.CatalogResponse, error) {
	return &pdppb.CatalogResponse{CatalogJson: p.catalog}, nil
}

func TestStreamAppHelper(t *testing.T) {
	if os.Getenv("EXPOSURE_TEST_STREAM_PROCESS") != "1" {
		return
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamAppStartupAndShutdown(t *testing.T) {
	// The fake initially returns Unimplemented, showing HTTP readiness and
	// listener liveness do not imply support for streaming authorization.
	canonical := []byte(`{"schemaVersion":1,"providerId":"provider","generation":1,"capabilities":[]}`)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(canonical))
	catalog := fmt.Sprintf(`{"schemaVersion":1,"providerId":"provider","pepClientId":"pep","generation":1,"catalogDigest":%q,"capabilities":[],"issuedAt":"2020-01-01T00:00:00Z","expiresAt":%q,"authorizationMode":"user","pepPolicyRevision":1}`, digest, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	pdpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pdp := grpc.NewServer()
	enc := base64.RawURLEncoding.EncodeToString
	token := enc([]byte(`{"alg":"EdDSA","typ":"JWT"}`)) + "." + enc([]byte(`{"iss":"https://issuer.example","sub":"user","aud":["client","resource"],"azp":"client"}`)) + "." + enc([]byte("signature"))
	checker := &startupPDP{catalog: []byte(catalog), t: t, bearer: "Bearer " + token}
	pdppb.RegisterPolicyDecisionPointServer(pdp, checker)
	go pdp.Serve(pdpListener)
	t.Cleanup(func() { pdp.Stop(); pdpListener.Close() })

	desc := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("fixture.proto"), Package: proto.String("fixture"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("value"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()}}}, {Name: proto.String("Response"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("value"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum()}}}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Read"), InputType: proto.String(".fixture.Request"), OutputType: proto.String(".fixture.Response"), ServerStreaming: proto.Bool(true)}}}}}}}
	raw, err := proto.Marshal(desc)
	if err != nil {
		t.Fatal(err)
	}

	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			addresses := make([]string, 4)
			listeners := make([]net.Listener, len(addresses))
			for i := range listeners {
				listeners[i], err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addresses[i] = listeners[i].Addr().String()
				t.Cleanup(func() { listeners[i].Close() })
			}
			// Keep the fake adapter's port reserved. Release only the three ports
			// the child must bind; distinct reservations prevent collisions.
			for i := 0; i < 3; i++ {
				listeners[i].Close()
			}
			var adapterCalls atomic.Int64
			adapter := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
				adapterCalls.Add(1)
				md, _ := metadata.FromIncomingContext(stream.Context())
				for _, item := range []struct{ key, value string }{{"x-workspace", "workspace"}, {"x-page", "page1"}, {"x-commit", "commit1"}} {
					if got := md.Get(item.key); len(got) != 1 || got[0] != item.value {
						t.Errorf("unexpected adapter selector %s: %v", item.key, got)
					}
				}
				for _, key := range []string{"authorization", "x-organization-id", "x-grant-app-auth-key"} {
					if len(md.Get(key)) != 0 {
						t.Errorf("adapter received forbidden %s", key)
					}
				}
				var request wrapperspb.StringValue
				if err := stream.RecvMsg(&request); err != nil || request.Value != "request" {
					return status.Error(codes.InvalidArgument, "request mismatch")
				}
				if err := stream.RecvMsg(&wrapperspb.StringValue{}); err != io.EOF {
					return status.Error(codes.InvalidArgument, "request was not half-closed")
				}
				return stream.SendMsg(wrapperspb.Bytes([]byte("frame")))
			}))
			go adapter.Serve(listeners[3])
			t.Cleanup(adapter.Stop)
			streamPath := ""
			if enabled {
				config := map[string]any{"listen": addresses[2], "upstream": addresses[3], "method": "/fixture.Service/Read", "descriptor": raw, "descriptorDigest": fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), "organization": "org", "action": "read", "resourceType": "page", "resourceSelector": "x-page", "selectors": []string{"x-workspace", "x-page", "x-commit"}, "fixedSelectors": map[string]string{"x-workspace": "workspace"}, "maxWireBytes": 278528, "maxFrames": 5}
				b, marshalErr := json.Marshal(config)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				streamPath = filepath.Join(t.TempDir(), "stream.json")
				if err := os.WriteFile(streamPath, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestStreamAppHelper$")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "EXPOSURE_") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "EXPOSURE_TEST_STREAM_PROCESS=1", "EXPOSURE_PROXY_ENABLED=true", "EXPOSURE_PROVIDER_AUTHORIZATION_MODE=forward-user", "EXPOSURE_DATA_ADDR="+addresses[0], "EXPOSURE_ADMIN_ADDR="+addresses[1], "EXPOSURE_PROVIDER_ID=provider", "EXPOSURE_PEP_CLIENT_ID=pep", "EXPOSURE_PROVIDER_ORIGIN=http://127.0.0.1:12345", "EXPOSURE_EXPECTED_CATALOG_DIGEST="+digest, "EXPOSURE_GRANT_APP_AUTH_KEY=fixture-key", "EXPOSURE_AUTHN_LIMITER_KEY=fixture-limiter", "EXPOSURE_GRANT_GRPC_TARGET="+pdpListener.Addr().String(), "EXPOSURE_CREDENTIAL_MODE=goauthy", "EXPOSURE_GOAUTHY_ISSUER=https://issuer.example", "EXPOSURE_GOAUTHY_USER_CLIENT_ID=client", "EXPOSURE_GOAUTHY_USER_RESOURCE_AUDIENCE=resource", "EXPOSURE_STREAM_GRPC_FILE="+streamPath)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			stopped := false
			t.Cleanup(func() {
				if !stopped {
					_ = cmd.Process.Kill()
					<-done
				}
			})
			client := &http.Client{Timeout: 200 * time.Millisecond}
			defer client.CloseIdleConnections()
			get := func(path string) int {
				resp, getErr := client.Get("http://" + addresses[1] + path)
				if getErr != nil {
					return 0
				}
				resp.Body.Close()
				return resp.StatusCode
			}
			deadline := time.Now().Add(5 * time.Second)
			for get("/readyz") != http.StatusOK {
				if time.Now().After(deadline) {
					t.Fatal("HTTP readiness did not become ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			want := http.StatusNotFound
			if enabled {
				want = http.StatusOK
			}
			for get("/stream-healthz") != want {
				if time.Now().After(deadline) {
					t.Fatalf("stream liveness did not become %d", want)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if enabled {
				conn, dialErr := net.DialTimeout("tcp", addresses[2], time.Second)
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				conn.Close()
				grpcConn, dialErr := grpc.NewClient("passthrough:///"+addresses[2], grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithNoProxy())
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				defer grpcConn.Close()
				call := func() (*wrapperspb.BytesValue, error) {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token, "x-organization-id", "org", "x-workspace", "workspace", "x-page", "page1", "x-commit", "commit1"))
					stream, err := grpcConn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/fixture.Service/Read")
					if err != nil {
						return nil, err
					}
					if err := stream.SendMsg(wrapperspb.String("request")); err != nil {
						return nil, err
					}
					if err := stream.CloseSend(); err != nil {
						return nil, err
					}
					var frame wrapperspb.BytesValue
					if err := stream.RecvMsg(&frame); err != nil {
						return nil, err
					}
					if err := stream.RecvMsg(&wrapperspb.BytesValue{}); err != io.EOF {
						return nil, fmt.Errorf("stream termination: %v", err)
					}
					return &frame, nil
				}
				if _, err := call(); status.Code(err) != codes.Unavailable {
					t.Fatalf("unimplemented BatchCheck: got %v", err)
				}
				if checker.checks.Load() != 1 || adapterCalls.Load() != 0 {
					t.Fatalf("checks=%d upstream calls=%d", checker.checks.Load(), adapterCalls.Load())
				}
				checker.allow.Store(true)
				frame, err := call()
				if err != nil || string(frame.GetValue()) != "frame" {
					t.Fatalf("allowed stream frame=%v error=%v", frame, err)
				}
				if checker.checks.Load() != 3 || adapterCalls.Load() != 1 {
					t.Fatalf("checks=%d upstream calls=%d", checker.checks.Load(), adapterCalls.Load())
				}
			} else if conn, dialErr := net.DialTimeout("tcp", addresses[2], 100*time.Millisecond); dialErr == nil {
				conn.Close()
				t.Fatal("disabled stream listener accepted connection")
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				stopped = true
				if err != nil {
					t.Fatalf("graceful shutdown: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("application did not stop")
			}
			for _, addr := range addresses[:3] {
				ln, listenErr := net.Listen("tcp", addr)
				if listenErr != nil {
					t.Fatalf("listener %s was not released: %v", addr, listenErr)
				}
				ln.Close()
			}
		})
	}
}
