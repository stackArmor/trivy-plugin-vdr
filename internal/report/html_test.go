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
	scanReport := Build(sampleInventory(), []model.Finding{sampleFinding("CVE-2026-0001", "HIGH", 0.7)}, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	var buf bytes.Buffer

	if err := RenderHTML(&buf, scanReport, ""); err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"Namespace", "Internet-exposed findings", "Internet exposure", "Automatable",
		"Exploitation", "EPSS score", "Technical impact", "window.__VDR_REPORT__",
		"CVE-2026-0001",
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
	if strings.Contains(output, "https://") {
		t.Fatalf("HTML output should be standalone without remote dependencies:\n%s", output)
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
