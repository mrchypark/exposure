package capability

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestBusinessCatalogBindings(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cap := businessCapability{CapabilityID: "cap", Version: 1, Enabled: true, FullMethod: "/fixture.Service/Get", DescriptorDigest: shaBytes([]byte("descriptor")), ActionID: "read", ResourceType: "object", ResourceID: "fixed", MaxMessageBytes: 1024}
	cap.ContractDigest, _ = businessCapabilityDigest(cap)
	c := businessCatalog{SchemaVersion: 1, ProviderID: "provider", Generation: 1, Capabilities: []businessCapability{cap}, PepClientID: "pep", AuthorizationMode: "user", PepPolicyRevision: 7, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339)}
	c.CatalogDigest, _ = businessCatalogDigest(c)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseBusinessCatalog(raw, "provider", "pep", c.CatalogDigest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := parseBusinessCatalog(raw, "provider", "pep", c.CatalogDigest, now.Add(31*time.Second)); err == nil {
		t.Fatal("expired catalog accepted")
	}
	if _, err := parseBusinessCatalog(raw, "provider", "other", c.CatalogDigest, now); err == nil {
		t.Fatal("wrong PEP accepted")
	}
	tampered := strings.Replace(string(raw), `"resourceId":"fixed"`, `"resourceId":"other"`, 1)
	if _, err := parseBusinessCatalog([]byte(tampered), "provider", "pep", c.CatalogDigest, now); err == nil {
		t.Fatal("tampering accepted")
	}
}

func TestBusinessCanonicalAndDigestVectors(t *testing.T) {
	b, err := grpcCanonical(map[string]any{"text": "<\u2028>", "n": uint64(9007199254740993)})
	if err != nil || string(b) != "{\"n\":9007199254740993,\"text\":\"<\u2028>\"}" {
		t.Fatalf("canonical: %q %v", b, err)
	}
	if got := shaBytes([]byte{0x0a, 0x01, 0x78}); got != "sha256:fbc601aefa01f8692f1ee4ca767d28f0ee54083d0bbee08bcee1f2bb3b75e3b7" {
		t.Fatalf("message: %s", got)
	}
	if got := shaBytes(nil); got != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty: %s", got)
	}
	if got := credentialDigest("Bearer token"); got != "sha256:39db3edf489cb0fe39999aea8645fce9bffb7a089bc104ad8ffb8f3e702cad17" {
		t.Fatalf("credential: %s", got)
	}
}

func TestBusinessIndependentCatalogVectors(t *testing.T) {
	// Digests calculated separately over the sorted compact JSON fixture.
	cap := businessCapability{CapabilityID: "cap", Version: 1, Enabled: true, FullMethod: "/fixture.Service/Get", DescriptorDigest: "sha256:" + strings.Repeat("0", 64), ActionID: "read", ResourceType: "object", ResourceID: "fixed", MaxMessageBytes: 1024}
	var err error
	cap.ContractDigest, err = businessCapabilityDigest(cap)
	if err != nil || cap.ContractDigest != "sha256:edf61ac58994f909c9b9f6f5ddda529e81b5b95af06ec1135259e7f174ad7725" {
		t.Fatalf("capability: %s %v", cap.ContractDigest, err)
	}
	cat := businessCatalog{SchemaVersion: 1, ProviderID: "provider", Generation: 1, Capabilities: []businessCapability{cap}}
	digest, err := businessCatalogDigest(cat)
	if err != nil || digest != "sha256:9226ba2df5bc7f4b3b3cac4623f4a7a05e01c23fe193bc44994cec31bb2198eb" {
		t.Fatalf("catalog: %s %v", digest, err)
	}
}

func TestGrantCanonicalCatalogVectors(t *testing.T) {
	cap := businessCapability{CapabilityID: "read", Version: 1, Enabled: true, FullMethod: "/Service/Get", DescriptorDigest: "sha256:" + strings.Repeat("a", 64), ActionID: "example.read", ResourceType: "file", ResourceID: "fixed", MaxMessageBytes: 2048}
	var err error
	cap.ContractDigest, err = businessCapabilityDigest(cap)
	if err != nil || cap.ContractDigest != "sha256:b2d3c932d61062b1aabe9f884a1e7ae84f51efb9fe5653f78344cc4a77eae651" {
		t.Fatalf("Grant capability: %s %v", cap.ContractDigest, err)
	}
	cat := businessCatalog{SchemaVersion: 1, ProviderID: "example", Generation: 1, Capabilities: []businessCapability{cap}}
	digest, err := businessCatalogDigest(cat)
	if err != nil || digest != "sha256:b49180e800e37ef376a1a4a7865d6d96ba9406addd0e050c611775b0243b2471" {
		t.Fatalf("Grant catalog: %s %v", digest, err)
	}
}

func TestBusinessDescriptorRejectsTamperAndStreaming(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		f := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: proto.String("fixture.proto"), Package: proto.String("fixture"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Request")}, {Name: proto.String("Response")}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: proto.String("Get"), InputType: proto.String(".fixture.Request"), OutputType: proto.String(".fixture.Response"), ServerStreaming: proto.Bool(streaming)}}}}}}}
		raw, err := proto.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if got := validateBusinessMethod(raw, shaBytes(raw), "/fixture.Service/Get"); (got == nil) == streaming {
			t.Fatalf("streaming=%v error=%v", streaming, got)
		}
		if validateBusinessMethod(raw, "sha256:"+strings.Repeat("0", 64), "/fixture.Service/Get") == nil {
			t.Fatal("wrong digest accepted")
		}
		if validateBusinessMethod(raw, shaBytes(raw), "/fixture.Service/get") == nil {
			t.Fatal("wrong case accepted")
		}
	}
}
