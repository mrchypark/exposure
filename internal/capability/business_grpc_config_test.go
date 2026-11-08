package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestBusinessServerStartupConfig(t *testing.T) {
	desc := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("fixture.proto"), Package: proto.String("fixture"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request")}, {Name: proto.String("Response")}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Get"), InputType: proto.String(".fixture.Request"), OutputType: proto.String(".fixture.Response")}}}}}}}
	descBytes, err := proto.Marshal(desc)
	if err != nil {
		t.Fatal(err)
	}
	cap := businessCapability{CapabilityID: "cap", Version: 1, Enabled: true, FullMethod: "/fixture.Service/Get", DescriptorDigest: shaBytes(descBytes), ActionID: "read", ResourceType: "object", ResourceID: "fixed", MaxMessageBytes: 1024}
	cap.ContractDigest, _ = businessCapabilityDigest(cap)
	base := businessFile{Listen: "127.0.0.1:0", Upstream: "127.0.0.1:1234", CatalogDigest: shaBytes([]byte("catalog")), MaxMessageBytes: 1024, Methods: []businessFileMethod{{Capability: cap, Descriptor: descBytes}}}
	for _, tc := range []struct {
		name    string
		change  func(*businessFile)
		unknown bool
		want    bool
	}{
		{"valid", func(*businessFile) {}, false, true},
		{"zero listener", func(c *businessFile) { c.Listen = "127.0.0.1:0" }, false, false},
		{"public listener", func(c *businessFile) { c.Listen = "0.0.0.0:8080" }, false, false},
		{"hostname upstream", func(c *businessFile) { c.Upstream = "localhost:1234" }, false, false},
		{"oversize", func(c *businessFile) { c.MaxMessageBytes = grpcPayloadLimit + 1 }, false, false},
		{"descriptor mismatch", func(c *businessFile) { c.Methods[0].Descriptor = []byte("invalid") }, false, false},
		{"duplicate method", func(c *businessFile) { c.Methods = append(c.Methods, c.Methods[0]) }, false, false},
		{"unknown field", func(*businessFile) {}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { reserved.Close() })
			c := base
			c.Listen = reserved.Addr().String()
			c.Methods = append([]businessFileMethod(nil), base.Methods...)
			tc.change(&c)
			b, e := json.Marshal(c)
			if e != nil {
				t.Fatal(e)
			}
			if tc.unknown {
				b = []byte(strings.Replace(string(b), `"listen":`, `"unknown":true,"listen":`, 1))
			}
			path := filepath.Join(t.TempDir(), "business.json")
			if e := os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			p := &Proxy{cfg: config.ProxyConfig{CredentialMode: "goauthy", GoauthyUserClientID: "client", GoauthyUserResourceAudience: "resource"}, learner: &grpcLearner{timeout: time.Second}}
			server, e := p.newBusinessServer(path, reserved)
			if (e == nil) != tc.want {
				t.Fatalf("NewBusinessServer: %v", e)
			}
			if server != nil {
				server.Close()
			}
		})
	}
}

func TestBusinessReadyRequiresFreshMatchingCatalog(t *testing.T) {
	now := time.Now().UTC()
	cap := businessCapability{CapabilityID: "cap", Version: 1, Enabled: true, FullMethod: "/fixture.Service/Get", DescriptorDigest: shaBytes([]byte("descriptor")), ActionID: "read", ResourceType: "object", ResourceID: "fixed", MaxMessageBytes: 1024}
	cap.ContractDigest, _ = businessCapabilityDigest(cap)
	cat := businessCatalog{SchemaVersion: 1, ProviderID: "provider", PepClientID: "pep", Generation: 1, AuthorizationMode: "user", PepPolicyRevision: 7, Capabilities: []businessCapability{cap}, IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	cat.CatalogDigest, _ = businessCatalogDigest(cat)
	raw, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &businessTestPDP{catalog: raw}
	server := grpc.NewServer()
	pdppb.RegisterPolicyDecisionPointServer(server, fixture)
	go server.Serve(listener)
	t.Cleanup(func() { server.Stop(); listener.Close() })
	p := &Proxy{cfg: config.ProxyConfig{ProviderID: "provider", PepClientID: "pep", AppAuthKey: "key"}}
	if err := p.ConfigureGRPCLearner(listener.Addr().String(), "", "", time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.CloseGRPCLearner() })
	s := &BusinessServer{draft: &businessDraft{proxy: p, catalogPin: cat.CatalogDigest, allowed: map[string]businessCapability{cap.FullMethod: cap}}}
	if !s.Ready(context.Background()) {
		t.Fatal("fresh catalog rejected")
	}
	fixture.setCatalog([]byte(`{}`))
	if s.Ready(context.Background()) {
		t.Fatal("invalid catalog accepted")
	}
	cat.IssuedAt = now.Add(-30 * time.Second).Format(time.RFC3339Nano)
	cat.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	raw, _ = json.Marshal(cat)
	fixture.setCatalog(raw)
	if s.Ready(context.Background()) {
		t.Fatal("expired catalog accepted")
	}
	cat.IssuedAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	cat.ExpiresAt = now.Add(20 * time.Second).Format(time.RFC3339Nano)
	raw, _ = json.Marshal(cat)
	fixture.setCatalog(raw)
	changed := cap
	changed.ResourceID = "other"
	s.draft.allowed[cap.FullMethod] = changed
	if s.Ready(context.Background()) {
		t.Fatal("mismatched method accepted")
	}
	s.draft.allowed[cap.FullMethod] = cap
	server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if s.Ready(ctx) {
		t.Fatal("unavailable learner accepted")
	}
}

func TestBusinessServerRejectsMissingProfileAndLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "business.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), grpcPayloadLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Proxy{}).NewBusinessServer(path); err == nil {
		t.Fatal("missing learner accepted")
	}
	p := &Proxy{cfg: config.ProxyConfig{CredentialMode: "goauthy", GoauthyUserClientID: "client", GoauthyUserResourceAudience: "resource"}, learner: &grpcLearner{timeout: time.Second}}
	if _, err := p.NewBusinessServer(path); err == nil {
		t.Fatal("oversized file accepted")
	}
}
