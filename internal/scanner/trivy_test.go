package scanner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/model"
)

func TestTrivyRunnerBuildsImageScanCommand(t *testing.T) {
	fake := &fakeCommandRunner{
		stdout: []byte(`{"Results":[]}`),
	}
	runner := TrivyRunner{
		Binary:        "trivy-test",
		CommandRunner: fake,
	}

	_, err := runner.ScanImage(context.Background(), "registry.example.com/app:v1", 45*time.Second)
	if err != nil {
		t.Fatalf("ScanImage returned error: %v", err)
	}

	if fake.name != "trivy-test" {
		t.Fatalf("command name = %q, want trivy-test", fake.name)
	}
	wantArgs := []string{"image", "--format", "json", "--scanners", "vuln", "--timeout", "45s", "registry.example.com/app:v1"}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", fake.args, wantArgs)
	}
}

func TestTrivyRunnerParsesVulnerabilitiesFromMultipleResults(t *testing.T) {
	runner := TrivyRunner{
		Binary: "trivy",
		CommandRunner: &fakeCommandRunner{
			stdout: []byte(`{
				"Results": [
					{
						"Target": "libssl",
						"Vulnerabilities": [
							{
								"VulnerabilityID": "CVE-2026-0001",
								"PkgName": "openssl",
								"InstalledVersion": "1.1.1",
								"FixedVersion": "1.1.2",
								"Severity": "HIGH",
								"Title": "openssl issue",
								"Description": "bad openssl",
								"References": ["https://example.com/cve"],
								"Status": "fixed"
							}
						]
					},
					{
						"Target": "busybox",
						"Vulnerabilities": [
							{
								"VulnerabilityID": "CVE-2026-0002",
								"PkgName": "busybox",
								"InstalledVersion": "1.36.0",
								"Severity": "MEDIUM"
							}
						]
					}
				]
			}`),
		},
	}

	findings, err := runner.ScanImage(context.Background(), "registry.example.com/app:v1", time.Minute)
	if err != nil {
		t.Fatalf("ScanImage returned error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %#v", len(findings), findings)
	}
	first := findings[0]
	if first.ID != "CVE-2026-0001" ||
		first.ImageRef != "registry.example.com/app:v1" ||
		first.PackageName != "openssl" ||
		first.InstalledVersion != "1.1.1" ||
		first.FixedVersion != "1.1.2" ||
		first.Severity != "HIGH" ||
		first.Title != "openssl issue" ||
		first.Description != "bad openssl" ||
		first.Status != "fixed" {
		t.Fatalf("first finding did not preserve fields: %#v", first)
	}
	if !reflect.DeepEqual(first.References, []string{"https://example.com/cve"}) {
		t.Fatalf("References = %#v", first.References)
	}

	second := findings[1]
	if second.ID != "CVE-2026-0002" || second.PackageName != "busybox" || second.ImageRef != "registry.example.com/app:v1" {
		t.Fatalf("second finding did not parse from second result: %#v", second)
	}
}

func TestTrivyRunnerEmptyOrMissingVulnerabilitiesReturnsNoFindings(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{name: "empty results", json: `{"Results":[]}`},
		{name: "missing vulnerabilities", json: `{"Results":[{"Target":"alpine"}]}`},
		{name: "empty vulnerabilities", json: `{"Results":[{"Target":"alpine","Vulnerabilities":[]}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := TrivyRunner{CommandRunner: &fakeCommandRunner{stdout: []byte(tt.json)}}

			findings, err := runner.ScanImage(context.Background(), "alpine:3.20", time.Second)
			if err != nil {
				t.Fatalf("ScanImage returned error: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("len(findings) = %d, want 0: %#v", len(findings), findings)
			}
		})
	}
}

func TestTrivyRunnerIncludesStderrOnCommandFailure(t *testing.T) {
	runner := TrivyRunner{
		CommandRunner: &fakeCommandRunner{
			stderr: []byte("unable to pull image"),
			err:    errors.New("exit status 1"),
		},
	}

	_, err := runner.ScanImage(context.Background(), "missing:image", time.Second)
	if err == nil {
		t.Fatal("ScanImage returned nil error")
	}
	if !strings.Contains(err.Error(), "trivy image scan failed") ||
		!strings.Contains(err.Error(), "missing:image") ||
		!strings.Contains(err.Error(), "unable to pull image") {
		t.Fatalf("error = %q, want useful command failure with stderr", err.Error())
	}
}

func TestTrivyRunnerInvalidJSONReturnsUsefulError(t *testing.T) {
	runner := TrivyRunner{CommandRunner: &fakeCommandRunner{stdout: []byte(`not-json`)}}

	_, err := runner.ScanImage(context.Background(), "alpine:3.20", time.Second)
	if err == nil {
		t.Fatal("ScanImage returned nil error")
	}
	if !strings.Contains(err.Error(), "parse trivy JSON") {
		t.Fatalf("error = %q, want parse context", err.Error())
	}
}

func TestScanInventoryScansUniqueImagesAndFansOutAffectedResources(t *testing.T) {
	webRef := model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web", ContainerName: "app", ContainerType: "container"}
	jobRef := model.ResourceRef{APIVersion: "batch/v1", Kind: "Job", Namespace: "default", Name: "migrate", ContainerName: "app", ContainerType: "container"}
	apiRef := model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "prod", Name: "api", ContainerName: "api", ContainerType: "container"}
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/web:v1", NormalizedImage: "registry.example.com/web", Resources: []model.ResourceRef{webRef}},
			{ImageRef: "registry.example.com/web:v1", NormalizedImage: "registry.example.com/web", Resources: []model.ResourceRef{jobRef}},
			{ImageRef: "registry.example.com/api:v2", NormalizedImage: "registry.example.com/api", Resources: []model.ResourceRef{apiRef}},
		},
	}
	runner := &fakeImageRunner{
		findings: map[string][]model.Finding{
			"registry.example.com/web:v1": {{ID: "CVE-2026-0001", PackageName: "openssl", Severity: "HIGH"}},
			"registry.example.com/api:v2": {{ID: "CVE-2026-0002", PackageName: "busybox", Severity: "LOW"}},
		},
	}

	findings, err := ScanInventory(context.Background(), inventory, runner, 30*time.Second)
	if err != nil {
		t.Fatalf("ScanInventory returned error: %v", err)
	}

	if !reflect.DeepEqual(runner.images, []string{"registry.example.com/web:v1", "registry.example.com/api:v2"}) {
		t.Fatalf("scanned images = %#v, want each unique image once in inventory order", runner.images)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %#v", len(findings), findings)
	}

	webFinding := findings[0]
	if webFinding.ImageRef != "registry.example.com/web:v1" {
		t.Fatalf("web ImageRef = %q", webFinding.ImageRef)
	}
	if webFinding.NormalizedImage != "registry.example.com/web" {
		t.Fatalf("web NormalizedImage = %q", webFinding.NormalizedImage)
	}
	if !reflect.DeepEqual(webFinding.AffectedResources, []model.ResourceRef{webRef, jobRef}) {
		t.Fatalf("web affected resources = %#v", webFinding.AffectedResources)
	}

	apiFinding := findings[1]
	if apiFinding.ImageRef != "registry.example.com/api:v2" {
		t.Fatalf("api ImageRef = %q", apiFinding.ImageRef)
	}
	if apiFinding.NormalizedImage != "registry.example.com/api" {
		t.Fatalf("api NormalizedImage = %q", apiFinding.NormalizedImage)
	}
	if !reflect.DeepEqual(apiFinding.AffectedResources, []model.ResourceRef{apiRef}) {
		t.Fatalf("api affected resources = %#v", apiFinding.AffectedResources)
	}
}

type fakeCommandRunner struct {
	name   string
	args   []string
	stdout []byte
	stderr []byte
	err    error
}

func (f *fakeCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.name = name
	f.args = append([]string(nil), args...)
	return f.stdout, f.stderr, f.err
}

type fakeImageRunner struct {
	images   []string
	findings map[string][]model.Finding
}

func (f *fakeImageRunner) ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error) {
	f.images = append(f.images, image)
	return f.findings[image], nil
}
