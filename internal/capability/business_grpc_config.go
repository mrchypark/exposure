package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/exposure/internal/contracts"
	"github.com/mrchypark/exposure/internal/pdppb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// businessFile is an operator-reviewed, startup-only allowlist. Descriptor
// bytes are base64-encoded in JSON and pinned by each capability digest.
type businessFile struct {
	Listen          string               `json:"listen"`
	Upstream        string               `json:"upstream"`
	CatalogDigest   string               `json:"catalogDigest"`
	MaxMessageBytes int                  `json:"maxMessageBytes"`
	Methods         []businessFileMethod `json:"methods"`
}
type businessFileMethod struct {
	Capability businessCapability `json:"capability"`
	Descriptor []byte             `json:"descriptor"`
}

// BusinessServer is only a loopback, no-upstream-credential test listener.
type BusinessServer struct {
	server   *grpc.Server
	listener net.Listener
	draft    *businessDraft
}

// NewBusinessServer reads and validates a bounded immutable startup file.
func (p *Proxy) NewBusinessServer(path string) (*BusinessServer, error) {
	return p.newBusinessServer(path, nil)
}

// A reserved test listener avoids racing on an ephemeral port.
func (p *Proxy) newBusinessServer(path string, reserved net.Listener) (*BusinessServer, error) {
	if p == nil || p.learner == nil || p.cfg.CredentialMode != "goauthy" || p.cfg.GoauthyUserClientID == "" || p.cfg.GoauthyUserResourceAudience == "" {
		return nil, errors.New("business gRPC requires learner gRPC and Goauthy USER profile")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("business gRPC file must be regular")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("business gRPC file changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, grpcPayloadLimit+1))
	if err != nil || len(b) == 0 || len(b) > grpcPayloadLimit || !utf8.Valid(b) || rejectDuplicateJSONKeys(b) != nil {
		return nil, errors.New("invalid business gRPC file")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || !exactKeys(fields, "listen", "upstream", "catalogDigest", "maxMessageBytes", "methods") {
		return nil, errors.New("invalid business gRPC fields")
	}
	var rawMethods []map[string]json.RawMessage
	if json.Unmarshal(fields["methods"], &rawMethods) != nil || len(rawMethods) == 0 {
		return nil, errors.New("business methods required")
	}
	for _, m := range rawMethods {
		if !exactKeys(m, "capability", "descriptor") {
			return nil, errors.New("invalid business method")
		}
		var capFields map[string]json.RawMessage
		if json.Unmarshal(m["capability"], &capFields) != nil || !exactKeys(capFields, "capabilityId", "version", "enabled", "fullMethod", "descriptorDigest", "actionId", "resourceType", "resourceId", "maxMessageBytes", "contractDigest") {
			return nil, errors.New("invalid business capability fields")
		}
	}
	var c businessFile
	if strictJSON(b, &c) != nil || !contracts.IsDigest(c.CatalogDigest) || c.MaxMessageBytes <= 0 || c.MaxMessageBytes > grpcPayloadLimit || !loopbackAddress(c.Listen, false) || !loopbackAddress(c.Upstream, false) {
		return nil, errors.New("invalid business gRPC config")
	}
	desc := make(map[string][]byte)
	allowed := make(map[string]businessCapability)
	for _, m := range c.Methods {
		cap := m.Capability
		digest, e := businessCapabilityDigest(cap)
		if !cap.Enabled || cap.CapabilityID == "" || cap.Version == 0 || cap.ActionID == "" || cap.ResourceType == "" || cap.ResourceID == "" || cap.MaxMessageBytes == 0 || cap.MaxMessageBytes > uint64(c.MaxMessageBytes) || e != nil || digest != cap.ContractDigest || validateBusinessMethod(m.Descriptor, cap.DescriptorDigest, cap.FullMethod) != nil {
			return nil, errors.New("invalid business capability")
		}
		if _, ok := allowed[cap.FullMethod]; ok {
			return nil, errors.New("duplicate business method")
		}
		if existing, ok := desc[cap.DescriptorDigest]; ok && string(existing) != string(m.Descriptor) {
			return nil, errors.New("descriptor collision")
		}
		allowed[cap.FullMethod] = cap
		desc[cap.DescriptorDigest] = m.Descriptor
	}
	d, err := newBusinessDraft(p, c.Upstream, desc, allowed, c.CatalogDigest, c.MaxMessageBytes)
	if err != nil {
		return nil, err
	}
	server, err := d.newServer()
	if err != nil {
		d.upstream.Close()
		return nil, err
	}
	listener := reserved
	if listener != nil {
		if listener.Addr().Network() != "tcp" || listener.Addr().String() != c.Listen {
			d.upstream.Close()
			return nil, errors.New("reserved listener mismatch")
		}
	} else {
		listener, err = net.Listen("tcp", c.Listen)
		if err != nil {
			d.upstream.Close()
			return nil, fmt.Errorf("business listener: %w", err)
		}
	}
	return &BusinessServer{server: server, listener: listener, draft: d}, nil
}

func loopbackAddress(addr string, allowZero bool) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	n, e := strconv.Atoi(port)
	return ip != nil && ip.IsLoopback() && e == nil && n >= 0 && n <= 65535 && (allowZero || n > 0) && strconv.Itoa(n) == port
}

func (s *BusinessServer) Serve() error { return s.server.Serve(s.listener) }
func (s *BusinessServer) Close()       { s.server.Stop(); s.listener.Close(); s.draft.upstream.Close() }

// Ready fetches a fresh pinned catalog and confirms every configured method.
func (s *BusinessServer) Ready(parent context.Context) bool {
	if s == nil || s.draft == nil || s.draft.proxy == nil || s.draft.proxy.learner == nil {
		return false
	}
	d := s.draft
	ctx, cancel := context.WithTimeout(parent, d.proxy.learner.timeout)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-grant-app-auth-key", d.proxy.cfg.AppAuthKey))
	response, err := d.proxy.learner.client.GetGrpcCatalog(ctx, &pdppb.CatalogRequest{ProviderId: d.proxy.cfg.ProviderID})
	if err != nil {
		return false
	}
	cat, err := parseBusinessCatalog(response.GetCatalogJson(), d.proxy.cfg.ProviderID, d.proxy.cfg.PepClientID, d.catalogPin, time.Now().UTC())
	if err != nil {
		return false
	}
	for method, approved := range d.allowed {
		found := false
		for _, capability := range cat.Capabilities {
			if capability.FullMethod == method && capability.Enabled && capability == approved {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
