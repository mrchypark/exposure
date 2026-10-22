package capability

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Call only for an owned Grant fixture, after populating its authentication headers.
func addGrantActionPrecondition(t *testing.T, client *http.Client, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodPut || !strings.HasSuffix(request.URL.Path, "/actions") {
		return
	}
	read, err := http.NewRequestWithContext(request.Context(), http.MethodGet, request.URL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	read.Header = request.Header.Clone()
	response, err := client.Do(read)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET action-set precondition: HTTP %d", response.StatusCode)
	}
	tag := response.Header.Get("ETag")
	if tag == "" {
		t.Fatal("Grant action-set GET omitted ETag")
	}
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("If-Match", tag)
}
