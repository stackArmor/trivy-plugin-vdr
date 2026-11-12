package diagnostics

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func readZip(t *testing.T, path string) map[string]string {
	t.Helper()
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	entries := map[string]string{}
	for _, file := range z.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		entries[file.Name] = string(data)
	}
	return entries
}

func TestCapturePreservesResponseAndRedactsArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support.zip")
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	b.SetScope([]string{"default"}, nil)
	raw := `{"kind":"PodList","apiVersion":"v1","items":[{"metadata":{"name":"migration","namespace":"default","ownerReferences":[{"kind":"Job","name":"migration","controller":true}],"managedFields":[{"sensitive":"hidden-managed"}],"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"kind\":\"Secret\",\"data\":{\"password\":\"hidden-annotation\"}}","helm.sh/hook":"post-install"}},"spec":{"containers":[{"name":"runner","image":"registry/migration:old","env":[{"name":"PASSWORD","value":"hidden-env"},{"name":"FROM_SECRET","valueFrom":{"secretKeyRef":{"name":"pull-secret","key":"password"}}}],"command":["hidden-command"],"args":["hidden-argument"]}]},"status":{"containerStatuses":[{"state":{"waiting":{"reason":"ImagePullBackOff","message":"failed pull MANIFEST_UNKNOWN https://user:hidden-userinfo@registry/image?token=hidden-query Authorization=hidden-header"}}}]}},{"metadata":{"name":"hidden-other-namespace","namespace":"other"}}]}`
	transport := b.WrapTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
	}))
	req, _ := http.NewRequest("GET", "https://server/api/v1/pods?token=hidden-request", nil)
	req.Header.Set("Authorization", "Bearer hidden-request-header")
	response, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(original) != raw {
		t.Fatal("scanner response changed")
	}
	b.AddJSON("scan/warnings.json", []string{"request failed: Bearer hidden-warning", "Authorization: Bearer hidden-authorization", `nested {"password":"hidden-nested"}`})
	b.AddJSON("scan/test.json", map[string]any{"kind": "Secret", "data": map[string]any{".dockerconfigjson": "hidden-secret"}})
	if err := b.Finish("completed with image scan failures"); err != nil {
		t.Fatal(err)
	}
	entries := readZip(t, path)
	var all strings.Builder
	for _, data := range entries {
		all.WriteString(data)
	}
	if strings.Contains(all.String(), "hidden-") {
		t.Fatalf("sensitive data leaked: %s", all.String())
	}
	for _, want := range []string{"ImagePullBackOff", "MANIFEST_UNKNOWN", "registry/migration:old", "post-install", "pull-secret", "secretKeyRef", "completed with image scan failures"} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("missing evidence %s", want)
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %v", info.Mode())
	}
	if _, err := New(path); err == nil {
		t.Fatal("existing archive accepted")
	}
}

func TestCaptureNamespaceListsAndCollectionGaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support.zip")
	b, _ := New(path)
	b.SetScope(nil, []string{"excluded"})
	calls := []struct {
		path   string
		status int
		body   string
	}{
		{"/api/v1/namespaces", 200, `{"kind":"NamespaceList","items":[{"metadata":{"name":"default"}},{"metadata":{"name":"excluded"}}]}`},
		{"/api/v1/namespaces/excluded/pods", 200, `{"kind":"Pod","metadata":{"name":"excluded-pod","namespace":"excluded"}}`},
		{"/api/v1/events", 403, `{"kind":"Status","reason":"Forbidden","message":"events is forbidden"}`},
		{"/apis/optional/v1/widgets", 404, `{"kind":"Status","reason":"NotFound"}`},
		{"/api/v1/nodes", 200, "not JSON"},
	}
	for _, call := range calls {
		tr := b.WrapTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: call.status, Body: io.NopCloser(strings.NewReader(call.body))}, nil
		}))
		req, _ := http.NewRequest("GET", "https://server"+call.path, nil)
		res, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	if err := b.Finish("partial"); err != nil {
		t.Fatal(err)
	}
	entries := readZip(t, path)
	for name, data := range entries {
		if strings.HasPrefix(name, "api/") && (strings.Contains(data, "name: excluded") || strings.Contains(data, "excluded-pod")) {
			t.Fatalf("scope leaked: %s", data)
		}
	}
	for _, want := range []string{"403", "Forbidden", "404", "NotFound", "non-JSON response omitted", "outside selected namespaces"} {
		var found bool
		for _, data := range entries {
			found = found || strings.Contains(data, want)
		}
		if !found {
			t.Errorf("missing gap %s", want)
		}
	}
}

func TestOversizedResponseIsReplayedButOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support.zip")
	b, _ := New(path)
	raw := strings.Repeat("x", maxResponseBytes+32)
	tr := b.WrapTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
	}))
	req, _ := http.NewRequest("GET", "https://server/api/v1/pods", nil)
	response, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(data) != raw {
		t.Fatal("oversized response changed")
	}
	if err := b.Finish("partial"); err != nil {
		t.Fatal(err)
	}
	entries := readZip(t, path)
	if len(entries) != 2 || !strings.Contains(entries["manifest.json"], "response size limit") {
		t.Fatalf("unexpected entries %v", entries)
	}
}

type failingBody struct{ sent bool }

func (b *failingBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, "partial"), nil
	}
	return 0, errors.New("broken response")
}
func (b *failingBody) Close() error { return nil }
func TestReadErrorStillReachesScanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support.zip")
	b, _ := New(path)
	tr := b.WrapTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: &failingBody{}}, nil
	}))
	req, _ := http.NewRequest("GET", "https://server/api/v1/pods", nil)
	res, _ := tr.RoundTrip(req)
	data, err := io.ReadAll(res.Body)
	res.Body.Close()
	if string(data) != "partial" || err == nil || !strings.Contains(err.Error(), "broken response") {
		t.Fatalf("data=%s err=%v", data, err)
	}
	b.size = maxBundleBytes
	b.AddJSON("scan/omitted.json", map[string]any{"value": "omitted"})
	if err := b.Finish("partial"); err != nil {
		t.Fatal(err)
	}
	all := readZip(t, path)
	if !strings.Contains(all["manifest.json"], "bundle size limit") {
		t.Fatal("missing limit record")
	}
}

func TestPublishingNeverOverwritesNewlyCreatedTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support.zip")
	b, _ := New(path)
	if err := os.WriteFile(path, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.Finish("success"); err == nil {
		t.Fatal("overwrote target")
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, []byte("keep me")) {
		t.Fatal("target changed")
	}
}

func TestConcurrentCapturesProduceReadableArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support.zip")
	bundle, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	transport := bundle.WrapTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"kind":"PodList","items":[]}`))}, nil
	}))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "https://server/api/v1/pods", nil)
			res, err := transport.RoundTrip(req)
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}()
	}
	wg.Wait()
	if err := bundle.Finish("success"); err != nil {
		t.Fatal(err)
	}
	if files := readZip(t, path); len(files) != 22 {
		t.Fatalf("archive contains %d files", len(files))
	}
}

func TestAnnotationsPreserveOperationalEvidenceAndRedactCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "support.zip")
	bundle, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle.AddJSON("scan/annotations.json", map[string]any{"metadata": map[string]any{"annotations": map[string]any{
		"example.com/deployment-id":                        "deploy-2026-11-12",
		"example.com/restart-reason":                       "recover-unhealthy-vproxy",
		"example.com/owner":                                "platform-team",
		"example.com/config":                               `{"backend":"vproxy","port":8080,"password":"hidden-embedded"}`,
		"example.com/quoted-token":                         `"Bearer hidden-quoted"`,
		"example.com/token":                                "hidden-token",
		"example.com/note":                                 "registry rejected Authorization: Bearer hidden-bearer",
		"helm.sh/hook":                                     "post-install,post-upgrade",
		"kubectl.kubernetes.io/last-applied-configuration": `{"kind":"Job","metadata":{"name":"migration"},"spec":{"template":{"spec":{"containers":[{"name":"runner","image":"registry/migration:v1","env":[{"name":"PASSWORD","value":"hidden-last-applied"}]}]}}}}`,
	}}})
	if err := bundle.Finish("success"); err != nil {
		t.Fatal(err)
	}
	content := readZip(t, path)["scan/annotations.json"]
	if strings.Contains(content, "hidden-") {
		t.Fatalf("annotation credential leaked: %s", content)
	}
	for _, want := range []string{"deploy-2026-11-12", "recover-unhealthy-vproxy", "platform-team", "vproxy", "8080", "post-install,post-upgrade", "registry/migration:v1"} {
		if !strings.Contains(content, want) {
			t.Errorf("lost operational annotation value %s", want)
		}
	}
}
