package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/stackArmor/trivy-plugin-vdr/internal/controlcredit"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
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

func TestBuildResourcesViewPreservesCloudRunIdentity(t *testing.T) {
	ref := model.ResourceRef{
		APIVersion:    "run.googleapis.com/v1",
		Kind:          "Service",
		Provider:      "gcp-cloud-run",
		Project:       "armory-gss-prod",
		Region:        "us-east4",
		Name:          "peregrine",
		ContainerName: "gateway",
		ContainerType: "container",
	}
	inventory := &model.Inventory{
		ContextName: "cloudrun/armory-gss-prod",
		Resources: []model.ResourceInventory{{
			Resource: model.ResourceRef{
				APIVersion: "run.googleapis.com/v1",
				Kind:       "Service",
				Provider:   "gcp-cloud-run",
				Project:    "armory-gss-prod",
				Region:     "us-east4",
				Name:       "peregrine",
			},
			Images: []model.ContainerImage{{
				Name:          "gateway",
				ContainerType: "container",
				ImageRef:      "us-east4-docker.pkg.dev/armory-gss-prod/peregrine/peregrine:1",
			}},
		}},
		Images: []model.ImageInventory{{
			ImageRef:  "us-east4-docker.pkg.dev/armory-gss-prod/peregrine/peregrine:1",
			Resources: []model.ResourceRef{ref},
		}},
	}

	got := Build(inventory, nil, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	if len(got.Resources) != 1 {
		t.Fatalf("resources = %d, want 1", len(got.Resources))
	}
	if got.Resources[0].Resource.Project != "armory-gss-prod" || got.Resources[0].Resource.Region != "us-east4" {
		t.Fatalf("resource identity = %#v, want project and region preserved", got.Resources[0].Resource)
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

func TestBuildScanReachabilityReportSuppressesScoringAndEnrichmentButKeepsExposureAndClassification(t *testing.T) {
	inv := sampleInventory()
	inv.Resources[0].Labels = map[string]string{"vdr.fedramp.io/asset-archetype": "dev-test"}
	finding := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	finding.Suppressed = true
	finding.Suppression = &model.Suppression{Source: "vex", Status: "affected"}
	exposures := map[model.ResourceRef]model.Exposure{
		sampleContainerRef(): {InternetAccessible: true, Provider: "gke", RouteKind: "Ingress", RouteName: "web"},
	}

	got := Build(inv, []model.Finding{finding}, exposures, Options{
		GeneratedAt:         fixedTime(),
		View:                ViewFindings,
		ClassificationOnly:  true,
		SuppressEnrichments: true,
	})

	if len(got.SuppressedFindings) != 1 {
		t.Fatalf("SuppressedFindings = %#v, want one suppressed finding", got.SuppressedFindings)
	}
	suppressed := got.SuppressedFindings[0]
	if suppressed.EPSS != nil || suppressed.Vulnrichment != nil {
		t.Fatalf("enrichment fields = %#v/%#v, want nil", suppressed.EPSS, suppressed.Vulnrichment)
	}
	if suppressed.Pain != nil || suppressed.Remediation != nil || suppressed.WouldHaveBeenPain != nil || suppressed.WouldHaveBeenRemediation != nil {
		t.Fatalf("scoring fields leaked in suppressed finding: %#v", suppressed)
	}
	if suppressed.Exposure == nil || !suppressed.Exposure.InternetAccessible {
		t.Fatalf("Exposure = %#v, want internet-reachable exposure", suppressed.Exposure)
	}
	if len(suppressed.Affected) != 1 {
		t.Fatalf("Affected = %#v, want one affected resource", suppressed.Affected)
	}
	affected := suppressed.Affected[0]
	if affected.Pain != nil || affected.Remediation != nil {
		t.Fatalf("affected scoring fields = %#v/%#v, want nil", affected.Pain, affected.Remediation)
	}
	if affected.Exposure == nil || !affected.Exposure.InternetAccessible {
		t.Fatalf("affected Exposure = %#v, want internet-reachable exposure", affected.Exposure)
	}
	if affected.Classification == nil {
		t.Fatalf("Classification missing from affected resource: %#v", affected)
	}
	if affected.Classification.Class != "B" || affected.Classification.Archetype != "dev-test" || affected.Classification.ArchetypeSource != "label" {
		t.Fatalf("Classification = %#v, want class B dev-test from label", affected.Classification)
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, got); err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}
	output := buf.String()
	for _, want := range []string{`"exposure"`, `"internetAccessible"`, `"classification"`, `"class"`, `"archetype"`} {
		if !strings.Contains(output, want) {
			t.Fatalf("JSON output missing %s:\n%s", want, output)
		}
	}
	for _, forbidden := range []string{`"epss"`, `"vulnrichment"`, `"pain"`, `"remediation"`, `"wouldHaveBeenPain"`, `"wouldHaveBeenRemediation"`} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("JSON output leaked %s:\n%s", forbidden, output)
		}
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

func TestBuildSeparatesSuppressedFindingsWithWouldHaveBeenPain(t *testing.T) {
	inv := sampleInventory()
	active := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	suppressed := sampleFinding("CVE-2026-0002", "HIGH", 0.7)
	suppressed.Suppressed = true
	suppressed.Suppression = &model.Suppression{
		Source:          "vex",
		Status:          "not_affected",
		Justification:   "vulnerable_code_not_in_execute_path",
		StatementSource: "VEX attestation in OCI registry",
	}
	exposures := map[model.ResourceRef]model.Exposure{sampleContainerRef(): {InternetAccessible: true, Provider: "gke", RouteKind: "Ingress", RouteName: "web"}}

	got := Build(inv, []model.Finding{active, suppressed}, exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings})

	if got.Summary.Findings != 1 {
		t.Fatalf("Summary.Findings = %d, want only active findings counted", got.Summary.Findings)
	}
	if len(got.Findings) != 1 || got.Findings[0].ID != "CVE-2026-0001" {
		t.Fatalf("Findings = %#v, want only active finding", got.Findings)
	}
	if len(got.SuppressedFindings) != 1 {
		t.Fatalf("SuppressedFindings = %#v, want one suppressed finding", got.SuppressedFindings)
	}
	gotSuppressed := got.SuppressedFindings[0]
	if gotSuppressed.ID != "CVE-2026-0002" || !gotSuppressed.Suppressed || gotSuppressed.Suppression == nil {
		t.Fatalf("suppressed finding = %#v, want VEX-dispositioned finding", gotSuppressed)
	}
	if gotSuppressed.Pain != nil || gotSuppressed.Remediation != nil {
		t.Fatalf("active Pain/Remediation = %#v/%#v, want nil for suppressed finding", gotSuppressed.Pain, gotSuppressed.Remediation)
	}
	if gotSuppressed.WouldHaveBeenPain == nil || gotSuppressed.WouldHaveBeenRemediation == nil {
		t.Fatalf("would-have-been Pain/Remediation missing: %#v", gotSuppressed)
	}
	if gotSuppressed.WouldHaveBeenPain.Tier == "" || gotSuppressed.WouldHaveBeenRemediation.Deadline == "" {
		t.Fatalf("would-have-been values incomplete: %#v/%#v", gotSuppressed.WouldHaveBeenPain, gotSuppressed.WouldHaveBeenRemediation)
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
	finding := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	finding.Status = "will_not_fix"
	finding.CWEs = []string{"CWE-787", "CWE-79"}
	report := model.Report{Findings: []model.Finding{finding}}
	var buf bytes.Buffer

	if err := RenderTable(&buf, report); err != nil {
		t.Fatalf("RenderTable returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{"ID", "PACKAGE", "SEVERITY", "STATUS", "EPSS", "AUTOMATABLE", "CWE", "CVE-2026-0001", "openssl 1.0.0 → no fix", "HIGH", "will_not_fix", "0.700", "CWE-787 (+1)"} {
		if !strings.Contains(output, want) {
			t.Fatalf("table output missing %q:\n%s", want, output)
		}
	}
}

func TestFormatCWEs(t *testing.T) {
	tests := []struct {
		name string
		cwes []string
		want string
	}{
		{name: "none", cwes: nil, want: ""},
		{name: "one", cwes: []string{"CWE-787"}, want: "CWE-787"},
		{name: "many", cwes: []string{"CWE-787", "CWE-79", "CWE-20"}, want: "CWE-787 (+2)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatCWEs(tt.cwes); got != tt.want {
				t.Fatalf("formatCWEs(%v) = %q, want %q", tt.cwes, got, tt.want)
			}
		})
	}
}

func TestBuildSummaryCountsFindingsWithSpecificCWE(t *testing.T) {
	inventory := &model.Inventory{
		ContextName: "ctx",
		Resources: []model.ResourceInventory{{
			Resource: sampleContainerRef(),
			Images:   []model.ContainerImage{{Name: "app", ContainerType: "container", ImageRef: "example/web:v1"}},
		}},
	}
	withCWE := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	withCWE.CWEs = []string{"CWE-787"}
	withoutCWE := sampleFinding("CVE-2026-0002", "LOW", 0.1)
	report := Build(inventory, []model.Finding{withCWE, withoutCWE}, nil, Options{GeneratedAt: fixedTime()})

	if report.Summary.Findings != 2 {
		t.Fatalf("Summary.Findings = %d, want 2", report.Summary.Findings)
	}
	if report.Summary.FindingsWithSpecificCWE != 1 {
		t.Fatalf("Summary.FindingsWithSpecificCWE = %d, want 1", report.Summary.FindingsWithSpecificCWE)
	}
}

func TestRenderClassificationOnlyTableOmitsScoringAndEnrichmentColumns(t *testing.T) {
	classification := &model.AssetClassification{Class: "B", Archetype: "dev-test", ArchetypeSource: "label"}
	report := model.Report{
		ClassificationOnly: true,
		Findings: []model.Finding{{
			ID:               "CVE-2026-0001",
			ImageRef:         "example/web:v1",
			PackageName:      "openssl",
			InstalledVersion: "1.0.0",
			Severity:         "HIGH",
			Exposure:         &model.Exposure{InternetAccessible: true, Provider: "gke", RouteKind: "Ingress", RouteName: "web"},
			AffectedResources: []model.ResourceRef{
				sampleContainerRef(),
			},
			Affected: []model.Affected{{
				Resource:       sampleContainerRef(),
				Classification: classification,
			}},
		}},
	}
	var buf bytes.Buffer

	if err := RenderTable(&buf, report); err != nil {
		t.Fatalf("RenderTable returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{"CLASS", "ASSET ARCHETYPE", "EXPOSED", "B", "dev-test (label)", "yes"} {
		if !strings.Contains(output, want) {
			t.Fatalf("table output missing %q:\n%s", want, output)
		}
	}
	for _, forbidden := range []string{"PAIN", "REMEDIATION", "EPSS", "AUTOMATABLE", "EXPLOITATION", "TECHNICAL IMPACT"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("table output leaked %q:\n%s", forbidden, output)
		}
	}
}

func TestFormatPackage(t *testing.T) {
	tests := []struct {
		name    string
		finding model.Finding
		want    string
	}{
		{"name installed and fixed", model.Finding{PackageName: "openssl", InstalledVersion: "1.0.0", FixedVersion: "1.1.0"}, "openssl 1.0.0 → 1.1.0"},
		{"no fix", model.Finding{PackageName: "openssl", InstalledVersion: "1.0.0"}, "openssl 1.0.0 → no fix"},
		{"name only", model.Finding{PackageName: "openssl"}, "openssl"},
		{"unknown package", model.Finding{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatPackage(tt.finding); got != tt.want {
				t.Errorf("formatPackage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderTableLabelsCloudFunctionsAsFunctions(t *testing.T) {
	finding := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	finding.AffectedResources = []model.ResourceRef{{
		APIVersion:    "run.googleapis.com/v1",
		Kind:          "Function",
		Provider:      "gcp-cloud-run",
		Project:       "armory-gss-prod",
		Region:        "us-east4",
		Name:          "processor",
		ContainerName: "worker",
		ContainerType: "container",
	}}
	report := model.Report{Findings: []model.Finding{finding}}
	var buf bytes.Buffer

	if err := RenderTable(&buf, report); err != nil {
		t.Fatalf("RenderTable returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Function/armory-gss-prod/us-east4/processor/worker") {
		t.Fatalf("table output should label Cloud Functions as Function, got:\n%s", output)
	}
	if strings.Contains(output, "Service/armory-gss-prod/us-east4/processor/worker") {
		t.Fatalf("table output should not label Cloud Functions as Service:\n%s", output)
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

// TestNoTaxonomyByteIdenticalScoring proves the control-credit engine is inert by
// default: a report built with no taxonomy is byte-identical to one built with an
// explicitly disabled taxonomy, and carries no control-credit fields.
func TestNoTaxonomyByteIdenticalScoring(t *testing.T) {
	inv := sampleInventory()
	findings := []model.Finding{sampleFinding("CVE-2026-0001", "HIGH", 0.7)}
	exposures := map[model.ResourceRef]model.Exposure{sampleContainerRef(): {InternetAccessible: true}}

	none := Build(inv, findings, exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings})
	disabled := Build(inv, findings, exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings, Taxonomy: controlcredit.Disabled()})

	nb, err := json.Marshal(none)
	if err != nil {
		t.Fatalf("marshal none: %v", err)
	}
	db, err := json.Marshal(disabled)
	if err != nil {
		t.Fatalf("marshal disabled: %v", err)
	}
	if !bytes.Equal(nb, db) {
		t.Fatalf("no-taxonomy vs disabled-taxonomy scoring diverged:\n none=%s\n disabled=%s", nb, db)
	}
	if strings.Contains(string(nb), "controlCredits") || strings.Contains(string(nb), "exploitability") {
		t.Fatalf("no-taxonomy report leaked control-credit fields: %s", nb)
	}
}

// TestTaxonomyAttachesExploitability proves the credit engine is wired into the
// report: with a taxonomy loaded, each finding carries an exploitability
// adjustment that echoes the published EPSS unchanged.
func TestTaxonomyAttachesExploitability(t *testing.T) {
	tax, err := controlcredit.Load(context.Background(), "../controlcredit/testdata/taxonomy")
	if err != nil || !tax.Enabled {
		t.Fatalf("load fixture taxonomy: %v (enabled=%v)", err, tax.Enabled)
	}
	inv := sampleInventory()
	f := sampleFinding("CVE-2026-0001", "HIGH", 0.9)
	f.CWEs = []string{"CWE-94"}
	f.Vulnrichment = &model.Vulnrichment{Exploitation: "none"}
	exposures := map[model.ResourceRef]model.Exposure{sampleContainerRef(): {InternetAccessible: true}}

	got := Build(inv, []model.Finding{f}, exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings, Taxonomy: tax})
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(got.Findings))
	}
	adj := got.Findings[0].Exploitability
	if adj == nil {
		t.Fatalf("exploitability not attached with a taxonomy loaded")
	}
	if adj.EPSS != 0.9 || adj.AdjustedEPSS != 0.9 {
		t.Fatalf("published EPSS mutated or wrong: %+v", adj)
	}
}
