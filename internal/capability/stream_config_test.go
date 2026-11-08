package capability

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/exposure/internal/config"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestStreamServerStartupConfig(t *testing.T) {
	desc := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("fixture.proto"), Package: proto.String("fixture"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request")}, {Name: proto.String("Response")}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Read"), InputType: proto.String(".fixture.Request"), OutputType: proto.String(".fixture.Response"), ServerStreaming: proto.Bool(true)}}}}}}}
	raw, err := proto.Marshal(desc)
	if err != nil {
		t.Fatal(err)
	}
	base := streamFile{Scope: "single-object", Upstream: "127.0.0.1:1234", Method: "/fixture.Service/Read", Descriptor: raw, DescriptorDigest: shaBytes(raw), Organization: "org", Action: "read", ResourceType: "page", ResourceSelector: "x-page", Selectors: []string{"x-workspace", "x-page", "x-commit"}, FixedSelectors: map[string]string{"x-workspace": "workspace"}, MaxWireBytes: streamResponseWireMax, MaxFrames: 5}
	for _, tc := range []struct {
		name   string
		change func(*streamFile)
		mutate func([]byte) []byte
		want   bool
	}{
		{"valid", func(*streamFile) {}, nil, true},
		{"missing scope", func(c *streamFile) { c.Scope = "" }, nil, false},
		{"multi-object scope", func(c *streamFile) { c.Scope = "multi-object" }, nil, false},
		{"omitted scope", func(*streamFile) {}, func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"scope":"single-object",`), nil, 1)
		}, false},
		{"max frames", func(c *streamFile) { c.MaxFrames = streamMaxFrames }, nil, true},
		{"zero frames", func(c *streamFile) { c.MaxFrames = 0 }, nil, false},
		{"too many frames", func(c *streamFile) { c.MaxFrames = streamMaxFrames + 1 }, nil, false},
		{"zero wire budget", func(c *streamFile) { c.MaxWireBytes = 0 }, nil, false},
		{"too much wire", func(c *streamFile) { c.MaxWireBytes = streamResponseWireMax + 1 }, nil, false},
		{"public listener", func(c *streamFile) { c.Listen = "0.0.0.0:8080" }, nil, false},
		{"zero listener", func(c *streamFile) { c.Listen = "127.0.0.1:0" }, nil, false},
		{"hostname upstream", func(c *streamFile) { c.Upstream = "localhost:1234" }, nil, false},
		{"remote upstream", func(c *streamFile) { c.Upstream = "192.0.2.1:1234" }, nil, false},
		{"self upstream", func(c *streamFile) { c.Upstream = c.Listen }, nil, false},
		{"descriptor mismatch", func(c *streamFile) { c.Descriptor = []byte("bad") }, nil, false},
		{"method mismatch", func(c *streamFile) { c.Method = "/fixture.Service/Other" }, nil, false},
		{"duplicate selector", func(c *streamFile) { c.Selectors = append(c.Selectors, "x-page") }, nil, false},
		{"missing resource selector", func(c *streamFile) { c.ResourceSelector = "x-missing" }, nil, false},
		{"resource is fixed", func(c *streamFile) { c.FixedSelectors["x-page"] = "page" }, nil, false},
		{"no fixed scope", func(c *streamFile) { c.FixedSelectors = map[string]string{} }, nil, false},
		{"credential selector", func(c *streamFile) { c.Selectors = append(c.Selectors, "authorization") }, nil, false},
		{"unknown field", func(*streamFile) {}, func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"listen":`), []byte(`"unknown":true,"listen":`), 1)
		}, false},
		{"duplicate field", func(*streamFile) {}, func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"maxFrames":5`), []byte(`"maxFrames":5,"maxFrames":5`), 1)
		}, false},
		{"case alias", func(*streamFile) {}, func(b []byte) []byte { return bytes.Replace(b, []byte(`"maxFrames":`), []byte(`"MaxFrames":`), 1) }, false},
		{"null field", func(*streamFile) {}, func(b []byte) []byte { return bytes.Replace(b, []byte(`"maxFrames":5`), []byte(`"maxFrames":null`), 1) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			c := base
			c.Listen = listener.Addr().String()
			c.Selectors = append([]string(nil), base.Selectors...)
			c.FixedSelectors = map[string]string{"x-workspace": "workspace"}
			tc.change(&c)
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if tc.mutate != nil {
				b = tc.mutate(b)
			}
			path := filepath.Join(t.TempDir(), "stream.json")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			p := &Proxy{cfg: config.ProxyConfig{CredentialMode: "goauthy", GoauthyUserClientID: "client", GoauthyUserResourceAudience: "resource", ProviderID: "provider", AppAuthKey: "key"}, learner: &grpcLearner{timeout: time.Second}}
			server, err := p.newStreamServer(path, listener)
			if (err == nil) != tc.want {
				t.Fatalf("newStreamServer: %v", err)
			}
			if server == nil {
				return
			}
			if server.Listening() {
				t.Fatal("not-yet-running server is ready")
			}
			go server.Serve()
			deadline := time.Now().Add(time.Second)
			for !server.Listening() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !server.Listening() {
				t.Fatal("bound server not ready")
			}
			server.Close()
			if server.Listening() {
				t.Fatal("closed server is ready")
			}
		})
	}
}

func TestStreamServerRejectsOversizeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stream.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), grpcPayloadLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	p := &Proxy{cfg: config.ProxyConfig{CredentialMode: "goauthy", GoauthyUserClientID: "client", GoauthyUserResourceAudience: "resource", ProviderID: "provider", AppAuthKey: "key"}, learner: &grpcLearner{timeout: time.Second}}
	if _, err := p.NewStreamServer(path); err == nil {
		t.Fatal("oversized file accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := p.NewStreamServer(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatal("symlink accepted")
	}
}
