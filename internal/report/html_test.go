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
	for _, want := range []string{"Namespace", "Internet exposed", "Automatable", "Exploitation", "EPSS score", "Technical impact", "Security", "privileged", "window.__VDR_REPORT__", "CVE-2026-0001"} {
		if !strings.Contains(output, want) {
			t.Fatalf("HTML output missing %q", want)
		}
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
