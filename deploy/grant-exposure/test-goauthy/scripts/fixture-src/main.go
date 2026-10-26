package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const host = "goauthy.grant-exposure-auth-test-v020.svc.cluster.local"
const issuer = "https://" + host + ":8443"
const clientID = "grant-exposure-v020-test"
const audience = "https://grant-exposure-v020.test/management"
const callback = "http://127.0.0.1:5555/callback"

func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func write(dir, name string, b []byte) error { return os.WriteFile(filepath.Join(dir, name), b, 0600) }
func read(dir, name string) (string, error) {
	b, e := os.ReadFile(filepath.Join(dir, name))
	return strings.TrimSpace(string(b)), e
}
func main() {
	dir := flag.String("dir", "", "private task directory")
	addr := flag.String("address", "127.0.0.1:18443", "owned port-forward address")
	flag.Parse()
	if *dir == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: fixture -dir PRIVATE_DIR [-address LOOPBACK:PORT] prepare|configuration|auth")
		os.Exit(2)
	}
	var e error
	switch flag.Arg(0) {
	case "prepare":
		e = prepare(*dir)
	case "auth":
		e = auth(*dir, *addr)
	case "configuration":
		var f *fixture
		f, e = newFixture(*dir, *addr)
		if e == nil {
			defer f.client.CloseIdleConnections()
			e = f.configuration()
			if e == nil {
				fmt.Println("PASS real Goauthy client-configuration Grant compatibility")
			}
		}
	default:
		e = errors.New("unsupported command")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "fixture failed:", e)
		os.Exit(1)
	}
}
func prepare(dir string) error {
	if _, e := os.Stat(filepath.Join(dir, "ca.pem")); !os.IsNotExist(e) {
		return errors.New("refusing to overwrite CA")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Exposure temporary Goauthy fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		return e
	}
	if e = write(dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return e
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e = x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if e != nil {
		return e
	}
	if e = write(dir, "tls.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return e
	}
	b, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		return e
	}
	return write(dir, "tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

type fixture struct {
	dir              string
	client           *http.Client
	secret, password string
}

func (f *fixture) request(method, path string, form url.Values, basic string) ([]byte, http.Header, int, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, e := http.NewRequest(method, issuer+path, body)
	if e != nil {
		return nil, nil, 0, e
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if basic != "" {
		req.SetBasicAuth(clientID, basic)
	}
	if path == "/oidc/client-configuration" {
		req.Header.Set("Accept-Encoding", "identity")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, e := f.client.Do(req)
	if e != nil {
		return nil, nil, 0, errors.New("verified HTTPS request failed")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.Header, resp.StatusCode, e
}
func (f *fixture) authorize() (string, string, string, error) {
	v, state := random(), random()
	sum := sha256.Sum256([]byte(v))
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {callback}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "state": {state}, "nonce": {random()}, "scope": {"openid goauthy.read"}, "resource": {audience}}
	b, _, status, e := f.request("GET", "/oidc/authorize?"+q.Encode(), nil, "")
	if e != nil {
		return "", "", "", e
	}
	if status != 200 {
		return "", "", "", fmt.Errorf("authorization form status %d", status)
	}
	m := regexp.MustCompile(`name="interaction"[^>]*value="([^"]+)"`).FindSubmatch(b)
	if len(m) != 2 {
		return "", "", "", errors.New("interaction absent")
	}
	return string(m[1]), v, state, nil
}
func newFixture(dir, addr string) (*fixture, error) {
	h, _, e := net.SplitHostPort(addr)
	if e != nil || net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback() {
		return nil, errors.New("port-forward must be literal loopback")
	}
	ca, e := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid CA")
	}
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != host+":8443" {
			return nil, errors.New("unexpected origin")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}}
	f := &fixture{dir: dir, client: &http.Client{Timeout: 10 * time.Second, Transport: transport, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	f.secret, e = read(dir, "credentials/bootstrap-client")
	if e != nil {
		return nil, e
	}
	return f, nil
}

func (f *fixture) configuration() error {
	b, h, status, err := f.request("GET", "/oidc/client-configuration", nil, f.secret)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("client-configuration status %d; not Grant-compatible", status)
	}
	return validateConfiguration(b, h)
}

func validateConfiguration(b []byte, h http.Header) error {
	media, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	sum := sha256.Sum256(b)
	if err != nil || media != "application/json" || len(h.Values("Content-Type")) != 1 || len(h.Values("Cache-Control")) != 1 || strings.TrimSpace(strings.ToLower(h.Get("Cache-Control"))) != "no-store" || len(h.Values("ETag")) != 1 || h.Get("ETag") != fmt.Sprintf(`"sha256:%x"`, sum) {
		return errors.New("client-configuration media/cache/ETag contract mismatch")
	}
	keys := json.NewDecoder(strings.NewReader(string(b)))
	first, err := keys.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("client-configuration must be an object")
	}
	seen := map[string]bool{}
	for keys.More() {
		key, err := keys.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return errors.New("client-configuration duplicate/invalid field")
		}
		seen[name] = true
		var raw json.RawMessage
		if keys.Decode(&raw) != nil {
			return errors.New("client-configuration malformed field")
		}
	}
	if len(seen) != 12 {
		return errors.New("client-configuration required field mismatch")
	}
	var v struct {
		Version         string   `json:"version"`
		Issuer          string   `json:"issuer"`
		ClientID        string   `json:"client_id"`
		Kind            string   `json:"client_kind"`
		Enabled         bool     `json:"enabled"`
		Confidential    bool     `json:"confidential"`
		Redirects       []string `json:"redirect_uris"`
		Grants          []string `json:"grant_types"`
		Scopes          []string `json:"scopes"`
		DefaultScopes   []string `json:"default_scopes"`
		Audience        []string `json:"audience"`
		DefaultAudience []string `json:"default_aud"`
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid client-configuration schema")
	}
	if v.Version != "goauthy.client-configuration.v1" || v.Issuer != issuer || v.ClientID != clientID || v.Kind != "bootstrap" || !v.Enabled || !v.Confidential || len(v.Redirects) != 1 || v.Redirects[0] != callback || len(v.DefaultAudience) != 1 || v.DefaultAudience[0] != audience {
		return errors.New("client-configuration identity/resource/redirect mismatch")
	}
	contains := func(values []string, expected string) bool {
		for _, value := range values {
			if value == expected {
				return true
			}
		}
		return false
	}
	for _, values := range [][]string{v.Redirects, v.Grants, v.Scopes, v.DefaultScopes, v.Audience, v.DefaultAudience} {
		if values == nil {
			return errors.New("client-configuration arrays must be present")
		}
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || seen[value] {
				return errors.New("client-configuration repeated/empty value")
			}
			seen[value] = true
		}
	}
	if !contains(v.Grants, "authorization_code") || !contains(v.Grants, "refresh_token") || !contains(v.Scopes, "openid") || !contains(v.Scopes, "goauthy.read") || !contains(v.Audience, audience) {
		return errors.New("client-configuration grants/scope/audience mismatch")
	}
	for _, scope := range v.DefaultScopes {
		if !contains(v.Scopes, scope) {
			return errors.New("client-configuration default scope not admitted")
		}
	}
	return nil
}

func auth(dir, addr string) error {
	f, e := newFixture(dir, addr)
	if e != nil {
		return e
	}
	defer f.client.CloseIdleConnections()
	if e = f.configuration(); e != nil {
		return e
	}
	f.password, e = read(dir, "credentials/admin-password")
	if e != nil {
		return e
	}
	b, _, status, e := f.request("POST", "/oidc/introspect", url.Values{"token": {"not-a-token"}}, "wrong-secret")
	if e != nil {
		return e
	}
	if status != 401 {
		return fmt.Errorf("invalid client credential status %d", status)
	}
	b, _, status, e = f.request("POST", "/oidc/introspect", url.Values{"token": {"not-a-token"}}, f.secret)
	if e != nil {
		return e
	}
	var inactive struct {
		Active bool `json:"active"`
	}
	if status != 200 || json.Unmarshal(b, &inactive) != nil || inactive.Active {
		return errors.New("unknown token not inactive")
	}
	interaction, verifier, state, e := f.authorize()
	if e != nil {
		return e
	}
	_, header, status, e := f.request("POST", "/auth/login", url.Values{"interaction": {interaction}, "username": {"fixture-admin"}, "password": {f.password}}, "")
	if e != nil {
		return e
	}
	if status != http.StatusSeeOther {
		return fmt.Errorf("real login status %d", status)
	}
	u, e := url.Parse(header.Get("Location"))
	if e != nil || u.Scheme != "http" || u.Host != "127.0.0.1:5555" || u.Path != "/callback" || u.Query().Get("state") != state || u.Query().Get("code") == "" {
		return errors.New("callback or state mismatch")
	}
	b, _, status, e = f.request("POST", "/oidc/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {u.Query().Get("code")}, "redirect_uri": {callback}, "code_verifier": {verifier}}, f.secret)
	if e != nil {
		return e
	}
	var token struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if status != 200 || json.Unmarshal(b, &token) != nil || token.Access == "" {
		return fmt.Errorf("authorization-code exchange status %d", status)
	}
	b, _, status, e = f.request("POST", "/oidc/introspect", url.Values{"token": {token.Access}}, f.secret)
	if e != nil {
		return e
	}
	var active struct {
		Active   bool     `json:"active"`
		Sub      string   `json:"sub"`
		Client   string   `json:"client_id"`
		Scope    string   `json:"scope"`
		Audience []string `json:"aud"`
	}
	if status != 200 || json.Unmarshal(b, &active) != nil || !active.Active || active.Sub == "" || active.Client != clientID {
		return errors.New("issued token introspection mismatch")
	}
	if len(active.Audience) != 1 || active.Audience[0] != audience || !strings.Contains(" "+active.Scope+" ", " openid ") || !strings.Contains(" "+active.Scope+" ", " goauthy.read ") {
		return errors.New("issued token audience/scope mismatch")
	}
	if e = write(dir, "user-access-token", []byte(token.Access)); e != nil {
		return e
	}
	if token.Refresh != "" {
		if e = write(dir, "user-refresh-token", []byte(token.Refresh)); e != nil {
			return e
		}
	}
	if e = write(dir, "user-subject", []byte(active.Sub)); e != nil {
		return e
	}
	fmt.Println("PASS real Goauthy client-configuration Grant contract, HTTPS login, authorization-code PKCE/state, issued-token introspection; invalid client rejected; unknown token inactive")
	fmt.Println("access-token-file", filepath.Join(dir, "user-access-token"))
	return nil
}
