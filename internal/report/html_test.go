package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestRenderHTMLUsesEmbeddedTemplateWithFiltersAndData(t *testing.T) {
	finding := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	finding.Status = "will_not_fix"
	finding.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L"
	finding.CWEs = []string{"CWE-94"}
	scanReport := Build(sampleInventory(), []model.Finding{finding}, map[model.ResourceRef]model.Exposure{
		sampleContainerRef(): {InternetAccessible: true},
	}, Options{GeneratedAt: fixedTime(), View: ViewResources})
	var buf bytes.Buffer

	if err := RenderHTML(&buf, scanReport, ""); err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"Namespace", "Internet-exposed findings", "Internet exposure", "Automatable",
		"Exploitation", "EPSS score", "Technical impact", "window.__VDR_REPORT__",
		"CVE-2026-0001",
		"packageLabel",            // package sub-line renderer present in the template
		"pkg-line",                // CSS/markup hook for the package sub-line under the CVE
		`"packageName":"openssl"`, // package data carried in the embedded report JSON

		"VDR Report",
		"Resource type",
		`id="resource-type"`,
		"Fix status",
		`id="status"`,
		"will_not_fix",
		"Fix available", // filter to hide findings with no available fix
		`id="fix-available"`,
		"fixAvailable", // row field the fix-available filter reads
		"Chainable entrypoint",
		`id="chainable-entrypoint"`,
		`"chainableEntrypoint"`,
		`"high_confidence"`,
		`"classification":"high_confidence"`,
		"chainableEntrypointTooltip",
		"entrypoint-badge",
		"entry.exposure || null", // finding rows must not inherit another affected resource's exposure
		"scopedRemediation",      // finding rows use their own affected-resource deadline
		"test-context",           // kubectx in the header
		"Certification Class",    // class chip/subtitle in the header
		"privileged",             // security posture moved into the resource-name tooltip
		"image-cell",             // long image references are constrained in the table
		"text-overflow: ellipsis",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("HTML output missing %q", want)
		}
	}
	// Security is no longer a column; it lives in the resource tooltip instead.
	if strings.Contains(output, "<th>Security</th>") {
		t.Fatalf("HTML output should not have a Security column header")
	}
	if strings.Contains(output, "<th>Chainable entrypoint</th>") {
		t.Fatalf("HTML output should not have a Chainable entrypoint column header")
	}
	if strings.Contains(output, "entry.exposure || finding.exposure") {
		t.Fatalf("HTML finding rows must not inherit top-level best exposure")
	}
	if strings.Contains(output, "VDR Kubernetes Report") {
		t.Fatalf("HTML output should use source-neutral report title")
	}
	if strings.Contains(output, "https://") {
		t.Fatalf("HTML output should be standalone without remote dependencies:\n%s", output)
	}
}

func TestRenderHTMLResourceTooltipIncludesCloudArmorPolicy(t *testing.T) {
	finding := sampleFinding("CVE-2026-0002", "HIGH", 0.7)
	exposures := map[model.ResourceRef]model.Exposure{
		sampleContainerRef(): {
			InternetAccessible: true,
			Provider:           "gke",
			RouteKind:          "HTTPRoute",
			RouteName:          "public-route",
			Protection: &model.AccessProtection{
				Provider: "gke",
				SecurityPolicy: &model.SecurityPolicy{
					Type:     "cloud-armor",
					Name:     "prod-armor",
					Provider: "gke",
				},
			},
		},
	}
	scanReport := Build(sampleInventory(), []model.Finding{finding}, exposures, Options{GeneratedAt: fixedTime(), View: ViewResources})
	var buf bytes.Buffer

	if err := RenderHTML(&buf, scanReport, ""); err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{"Cloud Armor: ", `"name":"prod-armor"`} {
		if !strings.Contains(output, want) {
			t.Fatalf("HTML output missing %q", want)
		}
	}
}

func TestRenderHTMLCloudRunOmitsNamespaceAndIncludesResourceTypeFilter(t *testing.T) {
	ref := model.ResourceRef{
		APIVersion:    "run.googleapis.com/v1",
		Kind:          "Function",
		Provider:      "gcp-cloud-run",
		Project:       "armory-gss-prod",
		Region:        "us-east4",
		Name:          "processor",
		ContainerName: "worker",
		ContainerType: "container",
	}
	inventory := &model.Inventory{
		ContextName: "cloudrun/armory-gss-prod",
		Resources: []model.ResourceInventory{{
			Resource: model.ResourceRef{
				APIVersion: "run.googleapis.com/v1",
				Kind:       "Function",
				Provider:   "gcp-cloud-run",
				Project:    "armory-gss-prod",
				Region:     "us-east4",
				Name:       "processor",
			},
			Images: []model.ContainerImage{{Name: "worker", ContainerType: "container", ImageRef: "example.com/fn:v1"}},
		}},
		Images: []model.ImageInventory{{ImageRef: "example.com/fn:v1", Resources: []model.ResourceRef{ref}}},
	}
	finding := sampleFinding("CVE-2026-0003", "HIGH", 0.7)
	finding.ImageRef = "example.com/fn:v1"
	finding.AffectedResources = []model.ResourceRef{ref}
	scanReport := Build(inventory, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	var buf bytes.Buffer

	if err := RenderHTML(&buf, scanReport, ""); err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{"Resource type", `id="resource-type"`, "Function"} {
		if !strings.Contains(output, want) {
			t.Fatalf("Cloud Run HTML output missing %q", want)
		}
	}
	for _, notWant := range []string{`id="namespace"`, "<th>Namespace</th>"} {
		if strings.Contains(output, notWant) {
			t.Fatalf("Cloud Run HTML output should omit %q", notWant)
		}
	}
}

func TestRenderHTMLSkipsResourcesWithoutFindingsInFindingsTable(t *testing.T) {
	scanReport := model.Report{
		ContextName: "cloudrun/p",
		Resources: []model.ResourceReport{{
			Resource: model.ResourceRef{
				APIVersion: "run.googleapis.com/v1",
				Kind:       "Job",
				Provider:   "gcp-cloud-run",
				Project:    "p",
				Region:     "us-east4",
				Name:       "migrate",
			},
			Findings: nil,
		}},
	}
	var buf bytes.Buffer

	if err := RenderHTML(&buf, scanReport, ""); err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "addFinding({}, resource.resource, resource.exposure, resource)") {
		t.Fatalf("HTML template still renders placeholder finding rows for resources with no findings")
	}
	if !strings.Contains(output, "const resourceFindings = resource.findings;") {
		t.Fatalf("HTML template should preserve null/undefined findings so parent metadata resources can be skipped")
	}
	if !strings.Contains(output, "if (!resourceFindings || resourceFindings.length === 0)") {
		t.Fatalf("HTML template should skip resources with null or empty findings")
	}
}

func TestRenderHTMLUsesCustomTemplate(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "custom.html")
	if err := os.WriteFile(templatePath, []byte(`<html><body>{{ .Report.Summary.Findings }} {{ .ReportJSON }}</body></html>`), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	var buf bytes.Buffer

	if err := RenderHTML(&buf, model.Report{Summary: model.Summary{Findings: 2}}, templatePath); err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "2") || !strings.Contains(buf.String(), "summary") {
		t.Fatalf("custom HTML output = %q, want rendered summary and JSON", buf.String())
	}
}
