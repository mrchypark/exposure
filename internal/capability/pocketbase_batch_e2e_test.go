package capability

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"testing"
)

// Shares the generated-catalog fixture and real Grant/PocketBase transports.
func runPocketBaseBatch(t *testing.T, origin string, rawRequest func(string, string, []byte, http.Header, int) []byte, request func(string, string, any, bool) (int, []byte), bind func(string, string, string, string), revoke func(string), capture *mutationCaptureTransport) {
	t.Helper()
	code, b := request("PATCH", origin+"/api/settings", map[string]any{"batch": map[string]any{"enabled": true, "maxRequests": 20, "timeout": 3, "maxBodySize": 128 << 20}}, true)
	if code != 200 {
		t.Fatalf("enable isolated native batch status%d: %s", code, b)
	}
	headers := http.Header{"Content-Type": {"application/json"}}
	post := func(body []byte, h http.Header, status int) {
		t.Helper()
		capture.mu.Lock()
		before := capture.decisions
		beforeUpstream := capture.calls
		capture.mu.Unlock()
		rawRequest("POST", "/api/batch", body, h, status)
		capture.mu.Lock()
		decisions := capture.decisions - before
		upstream := capture.calls - beforeUpstream
		capture.mu.Unlock()
		wantDecisions := 1
		if status == 422 {
			wantDecisions = 0
		}
		if decisions != wantDecisions {
			t.Fatalf("batch decisions %d want%d", decisions, wantDecisions)
		}
		if status == 403 || status == 422 {
			if upstream != 0 {
				t.Fatal("rejected batch reached PocketBase")
			}
		} else {
			if upstream != 1 {
				t.Fatalf("batch upstream calls%d", upstream)
			}
			capture.check(t, body, h.Get("Content-Type"))
		}
	}
	create := []byte("{ \n\"requests\": [{\"method\":\"POST\",\"url\":\"/api/collections/panelmaps/records\",\"body\":{\"data\":{\"fixture\":true},\"id\":\"batchnative001a\",\"plant\":\"fixtureplant01a\"}},{\"method\":\"POST\",\"url\":\"/api/collections/l17r68r7ddzqcij/records\",\"body\":{\"data\":{\"fixture\":true},\"plant\":\"fixtureplant01a\",\"id\":\"batchnative002a\"}}]}\n")
	bind("batch-create-panelmaps", "collection", "panelmaps", "mutation-operator")
	post(create, headers, 403) // child authority alone never grants root execution
	bind("batch-root", "batch", "patch-data", "mutation-operator")
	post(create, headers, 200)
	for _, id := range []string{"batchnative001a", "batchnative002a", "batchnative003a"} {
		defer request("DELETE", origin+"/api/collections/panelmaps/records/"+id, nil, true)
	}
	// A single unauthorized item denies the whole batch before any native write.
	patch := []byte(`{"requests":[{"method":"PATCH","url":"/api/collections/panelmaps/records/batchnative001a","body":{"plant":"mutationplant1a"}},{"method":"PATCH","url":"/api/collections/panelmaps/records/batchnative002a","body":{"plant":"mutationplant1a"}}]}`)
	bind("batch-record-one", "panelmaps", "batchnative001a", "mutation-operator")
	post(patch, headers, 403)
	code, b = request("GET", origin+"/api/collections/panelmaps/records/batchnative001a", nil, true)
	var untouched struct{ Plant string }
	if code != 200 || json.Unmarshal(b, &untouched) != nil || untouched.Plant != "fixtureplant01a" {
		t.Fatal("partially denied batch changed first record")
	}
	bind("batch-record-two", "panelmaps", "batchnative002a", "mutation-operator")
	post(patch, headers, 200)
	// Authorization succeeds, native validation failure still rolls back atomically.
	rollback := []byte(`{"requests":[{"method":"PATCH","url":"/api/collections/panelmaps/records/batchnative001a","body":{"plant":"fixtureplant01a"}},{"method":"POST","url":"/api/collections/panelmaps/records","body":{"data":{"fixture":true},"id":"batchnative002a"}}]}`)
	post(rollback, headers, 400)
	code, b = request("GET", origin+"/api/collections/panelmaps/records/batchnative001a", nil, true)
	if code != 200 || json.Unmarshal(b, &untouched) != nil || untouched.Plant != "mutationplant1a" {
		t.Fatal("native failed batch did not roll back")
	}
	// Supplied IDs require both create and update grants even when no row exists.
	upsert := []byte(`{"requests":[{"method":"PUT","url":"/api/collections/panelmaps/records","body":{"data":{"fixture":true},"id":"batchnative003a","plant":"fixtureplant01a"}}]}`)
	post(upsert, headers, 403)
	bind("batch-record-three", "panelmaps", "batchnative003a", "mutation-operator")
	post(upsert, headers, 200)                                                                                                                                          // native create branch
	post(upsert, headers, 200)                                                                                                                                          // native update branch, no pre-read by Exposure
	post([]byte(`{"requests":[{"method":"PUT","url":"/api/collections/panelmaps/records","body":{"plant":"fixtureplant01a","data":{"fixture":true}}}]}`), headers, 200) // omitted ID needs create only
	revoke("batch-create-panelmaps")
	post(upsert, headers, 403) // update grant alone cannot choose a branch
	revoke("batch-record-one")
	post(patch, headers, 403)
	// Malformed, nested, unrelated, or authority-overriding requests fail pre-PDP.
	for _, bad := range []string{`{"requests":[],"requests":[{"method":"POST","url":"/api/collections/panelmaps/records"}]}`, `{"requests":[{"method":"POST","url":"http://127.0.0.1:18202/api/collections/panelmaps/records"}]}`, `{"requests":[{"method":"POST","url":"/api/batch","body":{"requests":[]}}]}`, `{"requests":[{"method":"PATCH","url":"/api/collections/panelmaps/records/batchnative001a?expand=plant"}]}`, `{"requests":[{"method":"POST","url":"/api/collections/panelmaps/records","headers":{"Authorization":"override"}}]}`} {
		post([]byte(bad), headers, 422)
	}
	// Both native indexed multipart conventions keep the original payload bytes.
	bind("batch-create-files", "collection", "files", "mutation-operator")
	bind("batch-upsert-file", "files", "batchfile00001a", "mutation-operator")
	defer request("DELETE", origin+"/api/collections/files/records/batchfile00001a", nil, true)
	for i, field := range []string{"requests.0.file", "requests[0].file", "requests.0.file", "requests[0].file"} {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		payload := `{"requests":[{"method":"POST","url":"/api/collections/files/records","body":{"name":"Batch multipart"}}]}`
		if i >= 2 {
			payload = `{"requests":[{"method":"PUT","url":"/api/collections/files/records","body":{"id":"batchfile00001a","name":"Batch multipart upsert"}}]}`
		}
		if e := w.WriteField("@jsonPayload", payload); e != nil {
			t.Fatal(e)
		}
		part, e := w.CreateFormFile(field, "native.txt")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = part.Write([]byte("native batch file bytes\n")); e != nil {
			t.Fatal(e)
		}
		if e = w.Close(); e != nil {
			t.Fatal(e)
		}
		post(body.Bytes(), http.Header{"Content-Type": {w.FormDataContentType()}}, 200)
	}
	post([]byte(`{"requests":[{"method":"DELETE","url":"/api/collections/panelmaps/records/batchnative003a"}]}`), headers, 200)
	if code, _ := request("GET", origin+"/api/collections/panelmaps/records/batchnative003a", nil, true); code != 404 {
		t.Fatal("authorized native batch delete did not delete record")
	}
	revoke("batch-root")
	post([]byte(`{"requests":[{"method":"POST","url":"/api/collections/files/records","body":{"plant":"fixtureplant01a","data":{"fixture":true}}}]}`), headers, 403)
	t.Log("actual batch JSON/multipart/PUT: single root+children decision, unchanged one upstream request, no partial denied writes, native atomic rollback, create+update upsert grants and revocation passed")
}
