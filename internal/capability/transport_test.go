package capability

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestRawBodySpoolPreservesMultipartAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	var raw bytes.Buffer
	writer := multipart.NewWriter(&raw)
	part, err := writer.CreateFormFile("file", "native-file.bin")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0, 1, 2, 255, 13, 10}
	_, _ = part.Write(payload)
	_ = writer.WriteField("name", "unchanged")
	_ = writer.Close()
	policy := requestPolicy{Body: "multipart", MaxBytes: 65536, ContentTypes: []string{"multipart/form-data"}, ForwardHeaders: []string{"content-type"}}
	request := httptest.NewRequest("POST", "/api/collections/files/records", bytes.NewReader(raw.Bytes()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	body, err := readBody(request, policy, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if body.file == nil || body.length() != int64(raw.Len()) || body.digest() != shaBytes(raw.Bytes()) {
		t.Fatal("upload was not spooled and hashed exactly")
	}
	got, err := io.ReadAll(body.reader())
	if err != nil || !bytes.Equal(got, raw.Bytes()) {
		t.Fatal("multipart bytes changed")
	}
	filename := body.file.Name()
	body.close()
	if _, err = os.Stat(filename); !os.IsNotExist(err) {
		t.Fatal("upload file not removed")
	}
	request = httptest.NewRequest("POST", "/upload", strings.NewReader(strings.Repeat("x", 65537)))
	request.Header.Set("Content-Type", "application/octet-stream")
	policy.Body = "opaque"
	policy.ContentTypes = []string{"application/octet-stream"}
	if _, err = readBody(request, policy, 65536); err == nil {
		t.Fatal("oversize upload accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected upload leaked temporary file")
	}
}

func TestUTF8PathAndTextRepeatedQuery(t *testing.T) {
	params := []pathParameter{{Name: "file", Format: "utf8Segment", MaxBytes: 128}}
	captures, ok := matchTemplateParameters("/files/{id}/{file}", "/files/record/%ED%95%9C%EA%B8%80%20file.txt", params)
	if !ok || captures["file"] != "한글 file.txt" {
		t.Fatal("safe UTF8 path rejected")
	}
	for _, bad := range []string{"%2f", "%5c", "%25", "%2e%2e", "%00", "%ff"} {
		if _, ok = matchTemplateParameters("/files/{id}/{file}", "/files/record/"+bad, params); ok {
			t.Fatal("unsafe path escape accepted")
		}
	}
	if _, ok = matchTemplate("/files/{file}", "/files/a%20b"); ok {
		t.Fatal("undeclared UTF8 path accepted")
	}
	policy := queryPolicy{Mode: "exact", Parameters: []queryParam{{Name: "filter", Format: "text", MaxBytes: 128}, {Name: "tag", Format: "text", MaxBytes: 32, Repeated: true}}}
	canonical, err := canonicalQuery("tag=second&filter=name%3D%27a+b%27&tag=first", policy)
	if err != nil || canonical != "filter=name%3D%27a%20b%27&tag=second&tag=first" {
		t.Fatalf("canonical query=%q err=%v", canonical, err)
	}
	for _, bad := range []string{"filter=x&filter=y", "tag=%00", "unknown=x"} {
		if _, err = canonicalQuery(bad, policy); err == nil {
			t.Fatal("invalid query accepted")
		}
	}
}

func TestFileResponseRangeConditionalAndHEAD(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", "3")
			w.Header().Set("Content-Range", "bytes 1-3/5")
			w.WriteHeader(206)
			if r.Method != "HEAD" {
				_, _ = w.Write([]byte{0, 1, 255})
			}
		}))
		p := &Proxy{origin: transportURL(t, server.URL), http: server.Client()}
		p.cfg.MaxResponseBytes = 1024
		response := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/files/name", nil)
		p.forward(response, request, capability{Method: method, Response: responsePolicy{MaxBytes: 1024, ForwardHeaders: []string{"content-length", "content-range", "content-type"}}}, "", http.Header{}, nil)
		server.Close()
		if response.Code != 206 || response.Header().Get("Content-Length") != "3" || response.Header().Get("Content-Range") != "bytes 1-3/5" {
			t.Fatal("file metadata changed")
		}
		if method == http.MethodGet && !bytes.Equal(response.Body.Bytes(), []byte{0, 1, 255}) {
			t.Fatal("binary bytes changed")
		}
		if method == http.MethodHead && response.Body.Len() != 0 {
			t.Fatal("HEAD returned body")
		}
	}
}

func transportURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
