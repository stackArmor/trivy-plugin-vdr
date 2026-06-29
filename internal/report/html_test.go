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
	scanReport := Build(sampleInventory(), []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	var buf bytes.Buffer

	if err := RenderHTML(&buf, scanReport, ""); err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"Namespace", "Internet-exposed findings", "Internet exposure", "Automatable",
		"Exploitation", "EPSS score", "Technical impact", "window.__VDR_REPORT__",
		"CVE-2026-0001",
		"VDR Report",
		"Resource type",
		`id="resource-type"`,
		"Fix status",
		`id="status"`,
		"will_not_fix",
		"test-context",        // kubectx in the header
		"Certification Class", // class chip/subtitle in the header
		"privileged",          // security posture moved into the resource-name tooltip
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("HTML output missing %q", want)
		}
	}
	// Security is no longer a column; it lives in the resource tooltip instead.
	if strings.Contains(output, "<th>Security</th>") {
		t.Fatalf("HTML output should not have a Security column header")
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
