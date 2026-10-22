package capability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A body is completely bounded and hashed before an authorization request or
// upstream dispatch. Raw uploads stay on disk without changing their bytes.
type preparedBody struct {
	memory []byte
	file   *os.File
	size   int64
	sum    string
}

func (b *preparedBody) data() []byte {
	if b == nil {
		return nil
	}
	return b.memory
}
func (b *preparedBody) length() int64 {
	if b == nil {
		return 0
	}
	return b.size
}
func (b *preparedBody) digest() string {
	if b == nil {
		return shaBytes(nil)
	}
	return b.sum
}
func (b *preparedBody) reader() io.Reader {
	if b == nil {
		return nil
	}
	if b.file != nil {
		return b.file
	}
	return bytes.NewReader(b.memory)
}
func (b *preparedBody) close() {
	if b != nil && b.file != nil {
		name := b.file.Name()
		_ = b.file.Close()
		_ = os.Remove(name)
	}
}

func readBody(r *http.Request, policy requestPolicy, max int64) (*preparedBody, error) {
	if len(policy.ContentTypes) > 0 {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		allowed := false
		for _, item := range policy.ContentTypes {
			allowed = allowed || item == media
		}
		if err != nil || !allowed {
			return nil, errors.New("content type not allowed")
		}
	}
	if policy.Body == "none" || policy.Body == "json" {
		data, err := readJSONBody(r, policy, max)
		if err != nil {
			return nil, err
		}
		return &preparedBody{memory: data, size: int64(len(data)), sum: shaBytes(data)}, nil
	}
	if (policy.Body != "opaque" && policy.Body != "multipart") || policy.MaxBytes == 0 || max <= 0 || policy.MaxBytes > uint64(max) {
		return nil, errors.New("unsupported body policy")
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, errors.New("invalid content type")
	}
	allowed := false
	for _, value := range policy.ContentTypes {
		allowed = allowed || value == media
	}
	if !allowed {
		return nil, errors.New("content type not allowed")
	}
	if policy.Body == "multipart" && (media != "multipart/form-data" || params["boundary"] == "" || len(params["boundary"]) > 70) {
		return nil, errors.New("invalid multipart boundary")
	}
	file, err := os.CreateTemp("", "exposure-body-*")
	if err != nil {
		return nil, err
	}
	result := &preparedBody{file: file}
	ok := false
	defer func() {
		if !ok {
			result.close()
		}
	}()
	h := sha256.New()
	result.size, err = io.Copy(io.MultiWriter(file, h), io.LimitReader(r.Body, int64(policy.MaxBytes)+1))
	if err != nil {
		return nil, err
	}
	if uint64(result.size) > policy.MaxBytes {
		return nil, errors.New("body exceeds bound")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	result.sum = "sha256:" + hex.EncodeToString(h.Sum(nil))
	ok = true
	return result, nil
}

func validateTransportPolicy(c capability) error {
	prior := ""
	for _, parameter := range c.PathParameters {
		if parameter.Name <= prior || !strings.Contains(c.PathTemplate, "{"+parameter.Name+"}") || parameter.Format != "utf8Segment" || parameter.MaxBytes == 0 || parameter.MaxBytes > 4096 {
			return errors.New("invalid path parameter policy")
		}
		prior = parameter.Name
	}
	for _, parameter := range c.Query.Parameters {
		if parameter.Format == "text" && (parameter.MaxBytes == 0 || parameter.MaxBytes > 4096) || parameter.Format != "text" && parameter.MaxBytes != 0 {
			return errors.New("invalid query text bound")
		}
	}
	prior = ""
	for _, item := range c.Request.ContentTypes {
		media, params, err := mime.ParseMediaType(item)
		if err != nil || media != item || len(params) > 0 || item <= prior || c.Request.Body == "multipart" && item != "multipart/form-data" {
			return errors.New("invalid content type policy")
		}
		prior = item
	}
	if c.Request.Body == "opaque" || c.Request.Body == "multipart" {
		if c.Request.MaxBytes == 0 || len(c.Request.ContentTypes) == 0 {
			return errors.New("raw body requires explicit limits and media types")
		}
		if c.Resource != nil && c.Resource.ID.Kind == "jsonPointer" {
			return errors.New("raw body cannot use JSON extraction")
		}
	}
	if len(c.Request.ContentTypes) > 0 {
		if c.Request.Body == "none" {
			return errors.New("empty body cannot declare content types")
		}
		found := false
		for _, header := range c.Request.ForwardHeaders {
			found = found || header == "content-type"
		}
		if !found {
			return errors.New("content type must be forwarded and bound")
		}
	}
	return nil
}

func validText(value string, max uint64) bool {
	if max == 0 || max > 4096 || uint64(len(value)) > max || !utf8.ValidString(value) {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}
