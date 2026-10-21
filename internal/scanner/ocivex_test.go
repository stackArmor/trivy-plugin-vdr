package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/registry"
)

func readOCIVEXFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "ocivex", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func dsseFixture(t *testing.T, statementFixture string) []byte {
	t.Helper()
	envelope := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(readOCIVEXFixture(t, statementFixture)),
		"signatures":  []map[string]string{{"keyid": "", "sig": "MEUCIQ=="}},
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseOCIVEXAttestationKeepsJustificationAndDetail(t *testing.T) {
	statements, err := parseOCIVEXAttestation(dsseFixture(t, "cyclonedx-vex.statement.json"), "sha256:att1")
	if err != nil {
		t.Fatalf("parseOCIVEXAttestation returned error: %v", err)
	}
	// CVE-2026-0004 has no analysis and is not a VEX statement.
	if len(statements) != 3 {
		t.Fatalf("len(statements) = %d, want 3: %#v", len(statements), statements)
	}

	grpc := statements[0]
	if !reflect.DeepEqual(grpc.IDs, []string{"CVE-2026-33186"}) ||
		grpc.State != "not_affected" ||
		grpc.Justification != "code_not_reachable" ||
		grpc.Detail != "Ingress TLS terminates at Envoy; backend container only serves HTTP/1.1 health/metrics and never registers a gRPC server." ||
		!reflect.DeepEqual(grpc.Responses, []string{"will_not_fix"}) ||
		grpc.AttestationDigest != "sha256:att1" {
		t.Fatalf("statement[0] = %#v, want justification and detail both preserved", grpc)
	}
	if !reflect.DeepEqual(grpc.PURLs, []string{"pkg:golang/google.golang.org/grpc@v1.62.0"}) {
		t.Fatalf("statement[0].PURLs = %#v, want bom-ref resolved to purl", grpc.PURLs)
	}
	if grpc.Timestamp.IsZero() {
		t.Fatalf("statement[0].Timestamp is zero, want metadata.timestamp")
	}

	perimeter := statements[1]
	if perimeter.State != "exploitable" || perimeter.Justification != "protected_at_perimeter" ||
		perimeter.Detail != "WAF rule blocks the vulnerable request path." ||
		!reflect.DeepEqual(perimeter.Responses, []string{"workaround_available", "update"}) ||
		len(perimeter.PURLs) != 0 {
		t.Fatalf("statement[1] = %#v, want verbatim image-wide exploitable statement", perimeter)
	}

	alias := statements[2]
	if !reflect.DeepEqual(alias.IDs, []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-0003"}) || alias.State != "false_positive" || alias.Justification != "" {
		t.Fatalf("statement[2] = %#v, want GHSA id with CVE alias", alias)
	}
}

func TestParseOCIVEXAttestationAcceptsSigstoreBundle(t *testing.T) {
	var envelope map[string]any
	if err := json.Unmarshal(dsseFixture(t, "cyclonedx-vex.statement.json"), &envelope); err != nil {
		t.Fatal(err)
	}
	bundle, _ := json.Marshal(map[string]any{
		"mediaType":    "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": envelope,
	})
	statements, err := parseOCIVEXAttestation(bundle, "sha256:att2")
	if err != nil {
		t.Fatalf("parseOCIVEXAttestation returned error: %v", err)
	}
	if len(statements) != 3 || statements[0].Justification != "code_not_reachable" || statements[0].Detail == "" {
		t.Fatalf("statements = %#v, want CycloneDX statements from bundle", statements)
	}
}

func TestParseOCIVEXAttestationAcceptsCycloneDXBOMPredicate(t *testing.T) {
	statements, err := parseOCIVEXAttestation(dsseFixture(t, "cyclonedx-bom.statement.json"), "sha256:att3")
	if err != nil {
		t.Fatalf("parseOCIVEXAttestation returned error: %v", err)
	}
	if len(statements) != 1 || statements[0].IDs[0] != "CVE-2026-0005" || statements[0].State != "in_triage" || statements[0].Detail != "Under investigation." {
		t.Fatalf("statements = %#v, want BOM vulnerabilities[] statement", statements)
	}
}

func TestParseOCIVEXAttestationIgnoresNonCycloneDXPredicate(t *testing.T) {
	statements, err := parseOCIVEXAttestation(dsseFixture(t, "openvex.statement.json"), "sha256:att4")
	if !errors.Is(err, errNotCycloneDXVEX) {
		t.Fatalf("err = %v, want errNotCycloneDXVEX", err)
	}
	if len(statements) != 0 {
		t.Fatalf("statements = %#v, want none for OpenVEX", statements)
	}
}

func TestParseOCIVEXAttestationRejectsMalformedEnvelope(t *testing.T) {
	for name, data := range map[string][]byte{
		"bad payload":       readOCIVEXFixture(t, "malformed.envelope.json"),
		"not json":          []byte("{not json"),
		"not dsse":          []byte(`{"foo":"bar"}`),
		"wrong payloadType": []byte(`{"payloadType":"text/plain","payload":"aGVsbG8="}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseOCIVEXAttestation(data, "sha256:bad")
			if err == nil || errors.Is(err, errNotCycloneDXVEX) {
				t.Fatalf("err = %v, want a parse error", err)
			}
		})
	}
}

func TestAnnotateOCIVEXMatchesCVEComponentAndAliases(t *testing.T) {
	statements, err := parseOCIVEXAttestation(dsseFixture(t, "cyclonedx-vex.statement.json"), "sha256:att1")
	if err != nil {
		t.Fatal(err)
	}
	result := &OCIVEXResult{StatementSource: "oci://registry.example.com/app@sha256:1111", Statements: statements}
	findings := []model.Finding{
		{ID: "CVE-2026-33186", PackageName: "google.golang.org/grpc", PackagePURL: "pkg:golang/google.golang.org/grpc@v1.62.0", Severity: "HIGH"},
		// Same CVE in a different component: the component-scoped statement does not apply.
		{ID: "CVE-2026-33186", PackageName: "other/grpc-fork", PackagePURL: "pkg:golang/other/grpc-fork@v1.0.0", Severity: "HIGH"},
		{ID: "CVE-2026-0002", PackageName: "openssl", PackagePURL: "pkg:deb/debian/openssl@3.0.11?arch=amd64", Severity: "CRITICAL"},
		{ID: "CVE-2026-0003", PackageName: "vendored", Severity: "LOW"},
		{ID: "CVE-2026-0004", PackageName: "unanalysed", Severity: "HIGH"},
		{ID: "CVE-2026-9999", PackageName: "unrelated", Severity: "HIGH"},
	}

	if got := annotateOCIVEX(findings, result); got != 3 {
		t.Fatalf("annotateOCIVEX = %d, want 3", got)
	}
	want := &model.VEXAnalysis{
		Source:            "oci-cyclonedx-vex",
		Format:            "cyclonedx",
		State:             "not_affected",
		Justification:     "code_not_reachable",
		Detail:            "Ingress TLS terminates at Envoy; backend container only serves HTTP/1.1 health/metrics and never registers a gRPC server.",
		Responses:         []string{"will_not_fix"},
		StatementSource:   "oci://registry.example.com/app@sha256:1111",
		AttestationDigest: "sha256:att1",
	}
	if !reflect.DeepEqual(findings[0].VEX, want) {
		t.Fatalf("findings[0].VEX = %#v, want %#v", findings[0].VEX, want)
	}
	if findings[1].VEX != nil {
		t.Fatalf("findings[1].VEX = %#v, want nil for a component the statement does not name", findings[1].VEX)
	}
	if findings[2].VEX == nil || findings[2].VEX.State != "exploitable" || findings[2].VEX.Justification != "protected_at_perimeter" {
		t.Fatalf("findings[2].VEX = %#v, want image-wide exploitable statement", findings[2].VEX)
	}
	if findings[3].VEX == nil || findings[3].VEX.State != "false_positive" {
		t.Fatalf("findings[3].VEX = %#v, want statement matched through references[].id alias", findings[3].VEX)
	}
	if findings[4].VEX != nil || findings[5].VEX != nil {
		t.Fatalf("unmatched findings annotated: %#v / %#v", findings[4].VEX, findings[5].VEX)
	}
	for i, finding := range findings {
		if finding.Suppressed || finding.Suppression != nil {
			t.Fatalf("findings[%d] suppressed = %#v, want VEX annotation never to suppress", i, finding)
		}
	}
}

func TestSelectOCIVEXStatementPrefersComponentThenNewest(t *testing.T) {
	older := OCIVEXStatement{IDs: []string{"CVE-1"}, State: "in_triage"}
	newer := OCIVEXStatement{IDs: []string{"CVE-1"}, State: "not_affected", Timestamp: older.Timestamp.Add(1)}
	specific := OCIVEXStatement{IDs: []string{"CVE-1"}, State: "exploitable", PURLs: []string{"pkg:npm/lodash"}}
	finding := model.Finding{ID: "CVE-1", PackagePURL: "pkg:npm/lodash@4.17.20"}

	if got := selectOCIVEXStatement(finding, []OCIVEXStatement{older, newer}); got == nil || got.State != "not_affected" {
		t.Fatalf("selected = %#v, want newest image-wide statement", got)
	}
	if got := selectOCIVEXStatement(finding, []OCIVEXStatement{newer, specific}); got == nil || got.State != "exploitable" {
		t.Fatalf("selected = %#v, want component-scoped statement", got)
	}
}

// fakeVEXRegistry serves an image, an OCI 1.1 referrer carrying a Sigstore
// bundle, and a cosign .att tag, behind a bearer token challenge.
type fakeVEXRegistry struct {
	t        *testing.T
	server   *httptest.Server
	manifest map[string][]byte // by digest or tag
	blobs    map[string][]byte
	tokens   int
	noRefs   bool
}

func ociDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newFakeVEXRegistry(t *testing.T) *fakeVEXRegistry {
	r := &fakeVEXRegistry{t: t, manifest: map[string][]byte{}, blobs: map[string][]byte{}}
	r.server = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.server.Close)
	return r
}

func (r *fakeVEXRegistry) host() string {
	return strings.TrimPrefix(r.server.URL, "https://")
}

func (r *fakeVEXRegistry) addBlob(data []byte) string {
	digest := ociDigest(data)
	r.blobs[digest] = data
	return digest
}

func (r *fakeVEXRegistry) addManifest(value any, tags ...string) string {
	data, err := json.Marshal(value)
	if err != nil {
		r.t.Fatal(err)
	}
	digest := ociDigest(data)
	r.manifest[digest] = data
	for _, tag := range tags {
		r.manifest[tag] = data
	}
	return digest
}

func (r *fakeVEXRegistry) serve(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/token" {
		user, pass, ok := req.BasicAuth()
		if !ok || user != "robot" || pass != "secret" || req.URL.Query().Get("scope") != "repository:team/app:pull" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.tokens++
		_, _ = w.Write([]byte(`{"token":"tok"}`))
		return
	}
	if req.Header.Get("Authorization") != "Bearer tok" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+r.server.URL+`/token",service="fake",scope="repository:team/app:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	const prefix = "/v2/team/app/"
	path := strings.TrimPrefix(req.URL.Path, prefix)
	switch {
	case strings.HasPrefix(path, "manifests/"):
		data, ok := r.manifest[strings.TrimPrefix(path, "manifests/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Docker-Content-Digest", ociDigest(data))
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		if req.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	case strings.HasPrefix(path, "referrers/"):
		if r.noRefs {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		subject := strings.TrimPrefix(path, "referrers/")
		index := map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{}}
		if data, ok := r.manifest["referrers:"+subject]; ok {
			_ = json.Unmarshal(data, &index)
		}
		_ = json.NewEncoder(w).Encode(index)
	case strings.HasPrefix(path, "blobs/"):
		data, ok := r.blobs[strings.TrimPrefix(path, "blobs/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestRegistryVEXFetcherReadsReferrersAndAttTag(t *testing.T) {
	reg := newFakeVEXRegistry(t)
	imageDigest := reg.addManifest(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}, "v1")

	// cosign v3: OCI 1.1 referrer with a Sigstore bundle layer (CycloneDX BOM).
	var bomEnvelope map[string]any
	_ = json.Unmarshal(dsseFixture(t, "cyclonedx-bom.statement.json"), &bomEnvelope)
	bundle, _ := json.Marshal(map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "dsseEnvelope": bomEnvelope})
	bundleDigest := reg.addBlob(bundle)
	referrerDigest := reg.addManifest(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"artifactType":  "application/vnd.dev.sigstore.bundle.v0.3+json",
		"layers":        []any{map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "digest": bundleDigest, "size": len(bundle)}},
		"subject":       map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": imageDigest},
	})
	reg.addManifest(map[string]any{"manifests": []any{
		map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json", "digest": referrerDigest},
		map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": "application/vnd.example.sbom", "digest": "sha256:ignored"},
	}}, "referrers:"+imageDigest)

	// cosign v2: .att tag with a CycloneDX VEX layer and an OpenVEX layer that is
	// skipped by its predicateType annotation.
	vex := dsseFixture(t, "cyclonedx-vex.statement.json")
	openvex := dsseFixture(t, "openvex.statement.json")
	vexDigest := reg.addBlob(vex)
	openvexDigest := reg.addBlob(openvex)
	attDigest := reg.addManifest(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"layers": []any{
			map[string]any{"mediaType": "application/vnd.dsse.envelope.v1+json", "digest": openvexDigest, "size": len(openvex), "annotations": map[string]string{"predicateType": "https://openvex.dev/ns/v0.2.0"}},
			map[string]any{"mediaType": "application/vnd.dsse.envelope.v1+json", "digest": vexDigest, "size": len(vex), "annotations": map[string]string{"predicateType": "https://cyclonedx.org/vex"}},
		},
	}, strings.Replace(imageDigest, ":", "-", 1)+".att")

	fetcher := &registryVEXFetcher{
		auths:  map[string]registry.DockerAuth{reg.host(): {Username: "robot", Password: "secret"}},
		client: reg.server.Client(),
		scheme: "https",
	}
	result, err := fetcher.FetchVEX(context.Background(), reg.host()+"/team/app:v1")
	if err != nil {
		t.Fatalf("FetchVEX returned error: %v", err)
	}
	if result == nil {
		t.Fatal("FetchVEX returned nil result")
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", result.Warnings)
	}
	if want := "oci://" + reg.host() + "/team/app@" + imageDigest; result.StatementSource != want {
		t.Fatalf("StatementSource = %q, want %q", result.StatementSource, want)
	}
	digests := map[string]string{}
	for _, statement := range result.Statements {
		digests[statement.IDs[0]] = statement.AttestationDigest
	}
	if digests["CVE-2026-0005"] != referrerDigest {
		t.Fatalf("referrer statement digest = %q, want %q", digests["CVE-2026-0005"], referrerDigest)
	}
	if digests["CVE-2026-33186"] != attDigest {
		t.Fatalf(".att statement digest = %q, want %q", digests["CVE-2026-33186"], attDigest)
	}
	if len(result.Statements) != 4 {
		t.Fatalf("len(statements) = %d, want 1 referrer + 3 .att statements: %#v", len(result.Statements), result.Statements)
	}
	if reg.tokens == 0 {
		t.Fatal("registry token endpoint was never called")
	}
}

func TestRegistryVEXFetcherReturnsNilWithoutAttestations(t *testing.T) {
	reg := newFakeVEXRegistry(t)
	reg.noRefs = true
	reg.addManifest(map[string]any{"schemaVersion": 2}, "v1")
	fetcher := &registryVEXFetcher{
		auths:  map[string]registry.DockerAuth{reg.host(): {Username: "robot", Password: "secret"}},
		client: reg.server.Client(),
		scheme: "https",
	}
	result, err := fetcher.FetchVEX(context.Background(), reg.host()+"/team/app:v1")
	if err != nil || result != nil {
		t.Fatalf("FetchVEX = %#v, %v; want nil, nil", result, err)
	}
}

func TestRegistryVEXFetcherReportsUnauthorized(t *testing.T) {
	reg := newFakeVEXRegistry(t)
	reg.addManifest(map[string]any{"schemaVersion": 2}, "v1")
	fetcher := &registryVEXFetcher{client: reg.server.Client(), scheme: "https"}
	if _, err := fetcher.FetchVEX(context.Background(), reg.host()+"/team/app:v1"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want 401 token failure", err)
	}
}

func TestParseAuthChallenge(t *testing.T) {
	scheme, params := parseAuthChallenge(`Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:a/b:pull,push"`)
	want := map[string]string{"realm": "https://auth.example.com/token", "service": "registry.example.com", "scope": "repository:a/b:pull,push"}
	if scheme != "Bearer" || !reflect.DeepEqual(params, want) {
		t.Fatalf("parseAuthChallenge = %q %#v, want Bearer %#v", scheme, params, want)
	}
}
