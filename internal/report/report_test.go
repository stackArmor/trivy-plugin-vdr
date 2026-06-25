package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/matthewvenne/trivy-plugin-vdr/internal/model"
)

func TestBuildFindingViewKeepsAffectedResourcesAndSummary(t *testing.T) {
	inv := sampleInventory()
	findings := []model.Finding{sampleFinding("CVE-2026-0001", "HIGH", 0.7)}
	exposures := map[model.ResourceRef]model.Exposure{sampleContainerRef(): {InternetAccessible: true, Provider: "gke", RouteKind: "Ingress", RouteName: "web"}}

	got := Build(inv, findings, exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings})

	if got.Summary.Resources != 1 || got.Summary.Images != 1 || got.Summary.Findings != 1 || got.Summary.BySeverity["HIGH"] != 1 {
		t.Fatalf("Summary = %#v, want one resource/image/high finding", got.Summary)
	}
	if got.Summary.InternetAccessible != 1 {
		t.Fatalf("InternetAccessible summary = %d, want 1", got.Summary.InternetAccessible)
	}
	if len(got.Findings) != 1 || len(got.Findings[0].AffectedResources) != 1 {
		t.Fatalf("Findings = %#v, want finding with affected resource", got.Findings)
	}
	if len(got.Resources) != 0 {
		t.Fatalf("Resources len = %d, want 0 for finding view", len(got.Resources))
	}
}

func TestBuildFindingViewIncludesPerAffectedResourceExposure(t *testing.T) {
	inv := sampleInventory()
	exposed := sampleContainerRef()
	internal := model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "internal", ContainerName: "app", ContainerType: "container"}
	finding := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	finding.AffectedResources = []model.ResourceRef{exposed, internal}
	exposures := map[model.ResourceRef]model.Exposure{
		exposed: {InternetAccessible: true, Provider: "gke", RouteKind: "Ingress", RouteName: "web"},
	}

	got := Build(inv, []model.Finding{finding}, exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings})

	if len(got.Findings) != 1 || len(got.Findings[0].Affected) != 2 {
		t.Fatalf("Affected = %#v, want per-resource details for both affected resources", got.Findings)
	}
	for _, affected := range got.Findings[0].Affected {
		if affected.Resource == exposed && (affected.Exposure == nil || !affected.Exposure.InternetAccessible) {
			t.Fatalf("Affected exposed entry = %#v, want internet exposure", affected)
		}
		if affected.Resource == internal && affected.Exposure != nil {
			t.Fatalf("Affected internal entry = %#v, want no exposure", affected)
		}
	}
}

func TestBuildResourceViewIncludesSecurityAndExposure(t *testing.T) {
	inv := sampleInventory()
	findings := []model.Finding{sampleFinding("CVE-2026-0001", "HIGH", 0.7)}
	exposures := map[model.ResourceRef]model.Exposure{sampleContainerRef(): {InternetAccessible: true, Provider: "gke", RouteKind: "Ingress", RouteName: "web"}}

	got := Build(inv, findings, exposures, Options{GeneratedAt: fixedTime(), View: ViewResources})

	if len(got.Resources) != 1 {
		t.Fatalf("Resources len = %d, want 1: %#v", len(got.Resources), got.Resources)
	}
	resource := got.Resources[0]
	if resource.Resource.ContainerName != "app" {
		t.Fatalf("Resource = %#v, want app container ref", resource.Resource)
	}
	if resource.Exposure == nil || !resource.Exposure.InternetAccessible {
		t.Fatalf("Exposure = %#v, want internet accessible", resource.Exposure)
	}
	if len(resource.Images) != 1 || resource.Images[0].Security == nil || resource.Images[0].Security.Privileged == nil || !*resource.Images[0].Security.Privileged {
		t.Fatalf("Images = %#v, want container security metadata", resource.Images)
	}
	if len(resource.Findings) != 1 || resource.Findings[0].Exposure == nil || !resource.Findings[0].Exposure.InternetAccessible {
		t.Fatalf("Findings = %#v, want finding scoped to exposed resource", resource.Findings)
	}
}

func TestBuildResourceViewIncludesCleanInventoryResources(t *testing.T) {
	inv := sampleInventory()
	inv.Resources = append(inv.Resources, model.ResourceInventory{
		Resource: model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "clean"},
		Images: []model.ContainerImage{{
			Name:          "app",
			ContainerType: "container",
			ImageRef:      "example/clean:v1",
		}},
	})
	exposures := map[model.ResourceRef]model.Exposure{
		{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "clean", ContainerName: "app", ContainerType: "container"}: {
			InternetAccessible: true,
			Provider:           "gke",
			RouteKind:          "Ingress",
			RouteName:          "clean",
		},
	}

	got := Build(inv, nil, exposures, Options{GeneratedAt: fixedTime(), View: ViewResources})

	if len(got.Resources) != 2 {
		t.Fatalf("Resources len = %d, want all 2 inventory containers: %#v", len(got.Resources), got.Resources)
	}
	var clean *model.ResourceReport
	for i := range got.Resources {
		if got.Resources[i].Resource.Name == "clean" {
			clean = &got.Resources[i]
		}
	}
	if clean == nil {
		t.Fatalf("Resources = %#v, want clean resource without findings", got.Resources)
	}
	if len(clean.Findings) != 0 {
		t.Fatalf("clean Findings = %#v, want none", clean.Findings)
	}
	if clean.Exposure == nil || !clean.Exposure.InternetAccessible {
		t.Fatalf("clean Exposure = %#v, want internet accessible", clean.Exposure)
	}
	if got.Summary.InternetAccessible != 1 {
		t.Fatalf("InternetAccessible summary = %d, want 1 from full inventory exposure", got.Summary.InternetAccessible)
	}
}

func TestBuildFiltersBySeverityAndEPSS(t *testing.T) {
	inv := sampleInventory()
	findings := []model.Finding{
		sampleFinding("CVE-2026-0001", "MEDIUM", 0.9),
		sampleFinding("CVE-2026-0002", "CRITICAL", 0.2),
		sampleFinding("CVE-2026-0003", "HIGH", 0.8),
	}

	got := Build(inv, findings, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, MinSeverity: "HIGH", MinEPSS: 0.5})

	if len(got.Findings) != 1 || got.Findings[0].ID != "CVE-2026-0003" {
		t.Fatalf("Findings = %#v, want only high EPSS high-severity finding", got.Findings)
	}
	if got.Summary.Findings != 1 || got.Summary.BySeverity["HIGH"] != 1 {
		t.Fatalf("Summary = %#v, want one HIGH finding", got.Summary)
	}
}

func TestRenderJSONWritesSelectedView(t *testing.T) {
	report := model.Report{GeneratedAt: fixedTime(), Summary: model.Summary{Findings: 1}, Findings: []model.Finding{sampleFinding("CVE-2026-0001", "HIGH", 0.7)}}
	var buf bytes.Buffer

	if err := RenderJSON(&buf, report); err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}

	var decoded model.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON did not decode: %v\n%s", err, buf.String())
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].ID != "CVE-2026-0001" {
		t.Fatalf("decoded Findings = %#v, want CVE", decoded.Findings)
	}
}

func TestRenderTableIncludesResourceAndEnrichmentColumns(t *testing.T) {
	report := model.Report{Findings: []model.Finding{sampleFinding("CVE-2026-0001", "HIGH", 0.7)}}
	var buf bytes.Buffer

	if err := RenderTable(&buf, report); err != nil {
		t.Fatalf("RenderTable returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{"ID", "SEVERITY", "EPSS", "AUTOMATABLE", "CVE-2026-0001", "HIGH", "0.700"} {
		if !strings.Contains(output, want) {
			t.Fatalf("table output missing %q:\n%s", want, output)
		}
	}
}

func sampleInventory() *model.Inventory {
	privileged := true
	return &model.Inventory{
		ContextName: "test-context",
		Resources: []model.ResourceInventory{{
			Resource: model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web"},
			Labels:   map[string]string{"app": "web"},
			Images: []model.ContainerImage{{
				Name:          "app",
				ContainerType: "container",
				ImageRef:      "example/web:v1",
				Security:      &model.ContainerSecurity{Privileged: &privileged},
			}},
		}},
		Images: []model.ImageInventory{{
			ImageRef:  "example/web:v1",
			Resources: []model.ResourceRef{sampleContainerRef()},
		}},
	}
}

func sampleFinding(id, severity string, epssScore float64) model.Finding {
	return model.Finding{
		ID:               id,
		ImageRef:         "example/web:v1",
		PackageName:      "openssl",
		InstalledVersion: "1.0.0",
		Severity:         severity,
		EPSS:             &model.EPSS{Score: epssScore},
		Vulnrichment:     &model.Vulnrichment{Automatable: "yes", Exploitation: "active", TechnicalImpact: "total"},
		AffectedResources: []model.ResourceRef{
			sampleContainerRef(),
		},
	}
}

func sampleContainerRef() model.ResourceRef {
	return model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web", ContainerName: "app", ContainerType: "container"}
}

func fixedTime() time.Time {
	return time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
}
