// Package diagnostics writes bounded, redacted support bundles without changing
// the API responses consumed by the scanner.
package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/yaml"
)

const maxResponseBytes = 16 << 20
const maxBundleBytes = 128 << 20
const maxRecords = 10000

type Record struct {
	Path        string    `json:pathpkg "path"`
	CollectedAt time.Time `json:"collectedAt"`
	StatusCode  int       `json:"statusCode,omitempty"`
	File        string    `json:"file,omitempty"`
	Note        string    `json:"note,omitempty"`
	Kind        string    `json:"kind,omitempty"`
	Items       int       `json:"items,omitempty"`
}

type Bundle struct {
	mu                sync.Mutex
	file              *os.File
	archive           *zip.Writer
	target            string
	records           []Record
	started           time.Time
	size              int
	writeErr          error
	dropped           int
	closed            bool
	namespaces        []string
	excludeNamespaces []string
}

type contextKey struct{}

func WithBundle(ctx context.Context, bundle *Bundle) context.Context {
	return context.WithValue(ctx, contextKey{}, bundle)
}
func FromContext(ctx context.Context) *Bundle {
	bundle, _ := ctx.Value(contextKey{}).(*Bundle)
	return bundle
}

// New refuses to overwrite existing output and keeps the temporary ZIP private.
func New(target string) (*Bundle, error) {
	if _, err := os.Lstat(target); err == nil {
		return nil, fmt.Errorf("debug bundle already exists: %s", target)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(target), ".vdr-debug-*.zip")
	if err != nil {
		return nil, err
	}
	return &Bundle{file: f, archive: zip.NewWriter(f), target: target, started: time.Now().UTC()}, nil
}

func (b *Bundle) AddJSON(name string, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		b.Note(name, "could not encode diagnostic data")
		return
	}
	b.record(name, 0, data, false)
}

func (b *Bundle) Note(path, note string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	if len(b.records) >= maxRecords {
		b.dropped++
		return
	}
	b.records = append(b.records, Record{Path: path, CollectedAt: time.Now().UTC(), Note: note})
}

func (b *Bundle) record(path string, status int, data []byte, api bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	if len(b.records) >= maxRecords {
		b.dropped++
		return
	}
	rec := Record{Path: path, StatusCode: status, CollectedAt: time.Now().UTC()}
	defer func() { b.records = append(b.records, rec) }()
	if b.size >= maxBundleBytes {
		rec.Note = "bundle size limit reached; response omitted"
		return
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		rec.Note = "non-JSON response omitted"
		return
	}
	if b.excluded(value) {
		rec.Note = "outside selected namespaces; response omitted"
		return
	}
	value = b.filter(value)
	if obj, ok := value.(map[string]any); ok {
		rec.Kind, _ = obj["kind"].(string)
		if items, ok := obj["items"].([]any); ok {
			rec.Items = len(items)
		}
	}
	redact(value)
	clean, err := json.MarshalIndent(value, "", "  ")
	if err == nil && api {
		clean, err = yaml.JSONToYAML(clean)
	}
	if err != nil {
		rec.Note = "could not serialize redacted data"
		return
	}
	if b.size+len(clean) > maxBundleBytes {
		rec.Note = "bundle size limit reached; response omitted"
		return
	}
	name := path
	if api {
		resource := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
				return r
			}
			return '_'
		}, pathpkg.Base(path))
		name = fmt.Sprintf("api/%05d-%s.yaml", len(b.records)+1, resource)
	}
	if err := b.write(name, clean); err != nil {
		b.writeErr = err
		rec.Note = "archive write failed"
		return
	}
	rec.File = name
	b.size += len(clean)
}

// SetScope is called before the first API request; namespace filtering also applies
// to all-namespace responses, including supporting objects read by diagnostics.
func (b *Bundle) SetScope(namespaces, excluded []string) {
	b.namespaces = append([]string(nil), namespaces...)
	b.excludeNamespaces = append([]string(nil), excluded...)
}

func (b *Bundle) excluded(value any) bool {
	obj, ok := value.(map[string]any)
	if !ok {
		return false
	}
	meta, _ := obj["metadata"].(map[string]any)
	ns, _ := meta["namespace"].(string)
	if ns == "" {
		if obj["kind"] == "Namespace" {
			ns, _ = meta["name"].(string)
		} else {
			return false
		}
	}
	for _, excluded := range b.excludeNamespaces {
		if ns == excluded {
			return true
		}
	}
	if len(b.namespaces) > 0 {
		for _, included := range b.namespaces {
			if ns == included {
				return false
			}
		}
		return true
	}
	return false
}
func (b *Bundle) filter(value any) any {
	obj, ok := value.(map[string]any)
	if !ok {
		return value
	}
	if items, ok := obj["items"].([]any); ok {
		filtered := make([]any, 0, len(items))
		for _, item := range items {
			// NamespaceList items do not necessarily repeat kind/type metadata.
			if obj["kind"] == "NamespaceList" {
				if namespace, ok := item.(map[string]any); ok {
					namespace["kind"] = "Namespace"
				}
			}
			if !b.excluded(item) {
				filtered = append(filtered, b.filter(item))
			}
		}
		obj["items"] = filtered
	}
	return obj
}

func (b *Bundle) write(name string, data []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now().UTC()}
	header.SetMode(0600)
	entry, err := b.archive.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = entry.Write(data)
	return err
}

// Finish always attempts to preserve a partial bundle. Hard-linking publishes
// it without replacing an existing file, even if another process created it.
func (b *Bundle) Finish(outcome string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.writeErr
	}
	b.closed = true
	manifest := map[string]any{"schemaVersion": 1, "startedAt": b.started, "finishedAt": time.Now().UTC(), "outcome": outcome, "records": b.records, "droppedRecords": b.dropped, "maxResponseBytes": maxResponseBytes, "maxBundleBytes": maxBundleBytes}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err == nil {
		err = b.write("manifest.json", data)
	}
	if err != nil && b.writeErr == nil {
		b.writeErr = err
	}
	if err = b.write("README.txt", []byte(readme)); err != nil && b.writeErr == nil {
		b.writeErr = err
	}
	if err = b.archive.Close(); err != nil && b.writeErr == nil {
		b.writeErr = err
	}
	if err = b.file.Close(); err != nil && b.writeErr == nil {
		b.writeErr = err
	}
	defer os.Remove(b.file.Name())
	if err = os.Link(b.file.Name(), b.target); err != nil {
		b.writeErr = fmt.Errorf("publish debug bundle: %w", err)
		return b.writeErr
	}
	return b.writeErr
}

func (b *Bundle) WrapTransport(base http.RoundTripper) http.RoundTripper {
	return &captureTransport{base: base, bundle: b}
}

type captureTransport struct {
	base   http.RoundTripper
	bundle *Bundle
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if req.Method != "GET" {
		return response, err
	}
	path := req.URL.EscapedPath() // Never store headers, credentials, host, or query values.
	if req.URL.Query().Get("watch") == "true" || strings.HasSuffix(path, "/log") {
		t.bundle.Note(path, "streaming response omitted")
		return response, err
	}
	if err != nil {
		t.bundle.Note(path, "API transport failed")
		return response, err
	}
	if response.Body == nil {
		t.bundle.Note(path, "empty API response")
		return response, nil
	}
	original := response.Body
	data, readErr := io.ReadAll(io.LimitReader(original, maxResponseBytes+1))
	// Replay every byte to the caller, preserving any underlying read error.
	response.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(data), &errorReader{err: readErr}, original), Closer: original}
	if readErr != nil {
		t.bundle.Note(path, "API response could not be fully read")
		return response, nil
	}
	if len(data) > maxResponseBytes {
		t.bundle.Note(path, "response size limit reached; response omitted")
		return response, nil
	}
	t.bundle.record(path, response.StatusCode, data, true)
	return response, nil
}

type replayBody struct {
	io.Reader
	io.Closer
}
type errorReader struct{ err error }

func (r *errorReader) Read([]byte) (int, error) {
	if r.err != nil {
		err := r.err
		r.err = nil
		return 0, err
	}
	return 0, io.EOF
}

const readme = `VDR Kubernetes support bundle

manifest.json indexes timestamped API response snapshots and collection gaps.
api/*.yaml contains redacted GET responses from the scan and supporting reads.
scan/*.json contains selected scan settings, inventory and the report, when available.
Snapshots are collected over time, not an atomic cluster backup. Missing events
or denied API reads cannot be reconstructed; consult the manifest for omissions.
Only selected namespaces are retained. Cluster-scoped resources remain included.
Secret/ConfigMap values, literal environment values, command/argument contents,
HTTP header values and managedFields are omitted or redacted. Annotation values
are preserved except identified credential material. Embedded JSON annotations
receive structural redaction too. References to Secrets are retained.
Kubeconfig, request headers, local credentials, container logs and exec output
are not collected. Resource names, labels, images, internal addresses, events,
status messages and report findings remain: review before sharing externally.
Limits: 16 MiB per response, 128 MiB of archived payloads, 10000 records.
The diagnostics flag does not change a scan failure into success.
`
