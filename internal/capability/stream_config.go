package capability

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"google.golang.org/grpc"
)

// streamFile is an operator-reviewed, immutable pilot configuration. The
// upstream service, not this generic relay, verifies the object's raw size.
type streamFile struct {
	Scope            string            `json:"scope"`
	Listen           string            `json:"listen"`
	Upstream         string            `json:"upstream"`
	Method           string            `json:"method"`
	Descriptor       []byte            `json:"descriptor"`
	DescriptorDigest string            `json:"descriptorDigest"`
	Organization     string            `json:"organization"`
	Action           string            `json:"action"`
	ResourceType     string            `json:"resourceType"`
	ResourceSelector string            `json:"resourceSelector"`
	Selectors        []string          `json:"selectors"`
	FixedSelectors   map[string]string `json:"fixedSelectors"`
	MaxWireBytes     int               `json:"maxWireBytes"`
	MaxFrames        int               `json:"maxFrames"`
}

// StreamServer is a loopback-only pilot; loopback is not peer authentication.
type StreamServer struct {
	server   *grpc.Server
	listener net.Listener
	relay    *streamPilot
	active   atomic.Bool
	close    sync.Once
}

func (p *Proxy) NewStreamServer(path string) (*StreamServer, error) {
	return p.newStreamServer(path, nil)
}

func (p *Proxy) newStreamServer(path string, reserved net.Listener) (*StreamServer, error) {
	if p == nil || p.learner == nil {
		return nil, errors.New("stream requires a gRPC learner")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("stream configuration must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("stream configuration changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, grpcPayloadLimit+1))
	if err != nil || len(b) == 0 || len(b) > grpcPayloadLimit || !utf8.Valid(b) || rejectDuplicateJSONKeys(b) != nil {
		return nil, errors.New("invalid stream configuration")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || !exactKeys(fields, "scope", "listen", "upstream", "method", "descriptor", "descriptorDigest", "organization", "action", "resourceType", "resourceSelector", "selectors", "fixedSelectors", "maxWireBytes", "maxFrames") {
		return nil, errors.New("invalid stream configuration fields")
	}
	var c streamFile
	if strictJSON(b, &c) != nil || c.Scope != "single-object" || !loopbackAddress(c.Listen, false) || !loopbackAddress(c.Upstream, false) || c.Listen == c.Upstream {
		return nil, errors.New("invalid stream configuration values")
	}
	relay, err := newStreamPilot(p, c.Upstream, c.Method, c.Descriptor, c.DescriptorDigest, p.cfg.ProviderID, c.Organization, c.Action, c.ResourceType, c.ResourceSelector, c.Selectors, c.FixedSelectors, c.MaxWireBytes, c.MaxFrames)
	if err != nil {
		return nil, err
	}
	listener := reserved
	if listener != nil {
		if listener.Addr().Network() != "tcp" || listener.Addr().String() != c.Listen {
			relay.upstream.Close()
			return nil, errors.New("reserved listener mismatch")
		}
	} else {
		listener, err = net.Listen("tcp", c.Listen)
		if err != nil {
			relay.upstream.Close()
			return nil, fmt.Errorf("stream listener: %w", err)
		}
	}
	return &StreamServer{server: relay.server(), listener: listener, relay: relay}, nil
}

func (s *StreamServer) Serve() error {
	s.active.Store(true)
	defer s.active.Store(false)
	return s.server.Serve(s.listener)
}

func (s *StreamServer) Listening() bool { return s != nil && s.active.Load() }

func (s *StreamServer) Close() {
	s.close.Do(func() {
		s.active.Store(false)
		s.server.Stop()
		s.listener.Close()
		s.relay.upstream.Close()
	})
}
