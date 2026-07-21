package report

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func dedupeInventory() *model.Inventory {
	return &model.Inventory{
		ContextName: "test-context",
		Resources: []model.ResourceInventory{
			{
				Resource: model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web"},
				Images:   []model.ContainerImage{{Name: "app", ContainerType: "container", ImageRef: "example/web:v1"}},
			},
			{
				Resource: model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "api"},
				Images:   []model.ContainerImage{{Name: "app", ContainerType: "container", ImageRef: "example/api:v2"}},
			},
		},
		Images: []model.ImageInventory{
			{ImageRef: "example/web:v1", Resources: []model.ResourceRef{sampleContainerRef()}},
			{ImageRef: "example/api:v2", Resources: []model.ResourceRef{apiContainerRef()}},
		},
	}
}

func apiContainerRef() model.ResourceRef {
	return model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "api", ContainerName: "app", ContainerType: "container"}
}

func crossImageDuplicates() []model.Finding {
	web := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	api := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	api.ImageRef = "example/api:v2"
	api.AffectedResources = []model.ResourceRef{apiContainerRef()}
	return []model.Finding{web, api}
}

func TestBuildFindingsViewDedupeMergesAcrossImages(t *testing.T) {
	got := Build(dedupeInventory(), crossImageDuplicates(), nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Dedupe: true})

	if len(got.Findings) != 1 {
		t.Fatalf("Findings len = %d, want 1 merged finding: %#v", len(got.Findings), got.Findings)
	}
	merged := got.Findings[0]
	if merged.ImageRef != "example/api:v2" {
		t.Fatalf("survivor ImageRef = %q, want example/api:v2 (sorted first)", merged.ImageRef)
	}
	if !reflect.DeepEqual(merged.ImageRefs, []string{"example/api:v2", "example/web:v1"}) {
		t.Fatalf("ImageRefs = %#v, want both merged images sorted", merged.ImageRefs)
	}
	if len(merged.AffectedResources) != 2 || len(merged.Affected) != 2 {
		t.Fatalf("AffectedResources/Affected = %d/%d, want union of both refs", len(merged.AffectedResources), len(merged.Affected))
	}
	if got.Summary.Findings != 1 || got.Summary.BySeverity["HIGH"] != 1 {
		t.Fatalf("Summary = %#v, want deduplicated counts", got.Summary)
	}
}

func TestBuildFindingsViewDedupeKeepsWorstPain(t *testing.T) {
	exposures := map[model.ResourceRef]model.Exposure{
		apiContainerRef(): {InternetAccessible: true, Provider: "gke", RouteKind: "Ingress", RouteName: "api"},
	}

	got := Build(dedupeInventory(), crossImageDuplicates(), exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings, Dedupe: true})

	exposedOnly := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	exposedOnly.ImageRef = "example/api:v2"
	exposedOnly.AffectedResources = []model.ResourceRef{apiContainerRef()}
	want := Build(dedupeInventory(), []model.Finding{exposedOnly}, exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings})

	if len(got.Findings) != 1 || len(want.Findings) != 1 {
		t.Fatalf("Findings len = %d/%d, want 1 each", len(got.Findings), len(want.Findings))
	}
	if got.Findings[0].Pain == nil || !reflect.DeepEqual(got.Findings[0].Pain, want.Findings[0].Pain) {
		t.Fatalf("merged Pain = %#v, want worst-case pain of exposed ref %#v", got.Findings[0].Pain, want.Findings[0].Pain)
	}
	if got.Findings[0].Remediation == nil || !reflect.DeepEqual(got.Findings[0].Remediation, want.Findings[0].Remediation) {
		t.Fatalf("merged Remediation = %#v, want worst-case remediation of exposed ref %#v", got.Findings[0].Remediation, want.Findings[0].Remediation)
	}
}

func TestBuildFindingsViewDedupeKeepsHighestChainableEntrypointStatus(t *testing.T) {
	findings := crossImageDuplicates()
	findings[0].CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
	findings[0].CWEs = []string{"CWE-94"}
	findings[1].CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
	findings[1].CWEs = []string{"CWE-79"}

	got := Build(dedupeInventory(), findings, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Dedupe: true})

	if len(got.Findings) != 1 || got.Findings[0].ChainableEntrypoint == nil {
		t.Fatalf("Findings = %#v, want one finding with entrypoint metadata", got.Findings)
	}
	if got.Findings[0].ChainableEntrypoint.CandidateStatus != "high-confidence" {
		t.Fatalf("ChainableEntrypoint = %#v, want conservative high-confidence status", got.Findings[0].ChainableEntrypoint)
	}
}

func TestBuildFindingsViewDedupeOffKeepsDuplicates(t *testing.T) {
	got := Build(dedupeInventory(), crossImageDuplicates(), nil, Options{GeneratedAt: fixedTime(), View: ViewFindings})

	if len(got.Findings) != 2 || got.Summary.Findings != 2 {
		t.Fatalf("Findings/Summary.Findings = %d/%d, want 2 without --dedupe", len(got.Findings), got.Summary.Findings)
	}
	var out bytes.Buffer
	if err := RenderJSON(&out, got); err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}
	if strings.Contains(out.String(), "imageRefs") {
		t.Fatalf("JSON output should not contain imageRefs without --dedupe:\n%s", out.String())
	}
}

func TestBuildFindingsViewDedupeDistinctVersionsNotMerged(t *testing.T) {
	findings := crossImageDuplicates()
	findings[1].InstalledVersion = "1.0.1"

	got := Build(dedupeInventory(), findings, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Dedupe: true})

	if len(got.Findings) != 2 {
		t.Fatalf("Findings len = %d, want 2 for distinct installed versions: %#v", len(got.Findings), got.Findings)
	}
}

func TestBuildResourcesViewDedupeCollapsesTargets(t *testing.T) {
	first := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	first.Target = "usr/lib/a"
	second := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	second.Target = "usr/lib/b"
	findings := []model.Finding{first, second}

	got := Build(sampleInventory(), findings, nil, Options{GeneratedAt: fixedTime(), View: ViewResources, Dedupe: true})
	if len(got.Resources) != 1 || len(got.Resources[0].Findings) != 1 {
		t.Fatalf("Resources findings = %#v, want single deduplicated finding", got.Resources)
	}
	if got.Resources[0].Findings[0].ImageRef != "example/web:v1" {
		t.Fatalf("scoped ImageRef = %q, want the resource's image", got.Resources[0].Findings[0].ImageRef)
	}

	kept := Build(sampleInventory(), findings, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	if len(kept.Resources) != 1 || len(kept.Resources[0].Findings) != 2 {
		t.Fatalf("Resources findings = %#v, want both findings without --dedupe", kept.Resources)
	}
}

func TestBuildDedupeDropsDuplicateAffectedRefs(t *testing.T) {
	finding := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	finding.AffectedResources = []model.ResourceRef{sampleContainerRef(), sampleContainerRef()}

	findingsView := Build(sampleInventory(), []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Dedupe: true})
	if len(findingsView.Findings) != 1 || len(findingsView.Findings[0].Affected) != 1 {
		t.Fatalf("Findings = %#v, want single affected entry", findingsView.Findings)
	}

	resourcesView := Build(sampleInventory(), []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewResources, Dedupe: true})
	if len(resourcesView.Resources) != 1 || len(resourcesView.Resources[0].Findings) != 1 {
		t.Fatalf("Resources = %#v, want single scoped finding", resourcesView.Resources)
	}
}

func TestBuildDedupeMergesSuppressedFindings(t *testing.T) {
	findings := crossImageDuplicates()
	for i := range findings {
		findings[i].Suppressed = true
		findings[i].Suppression = &model.Suppression{Source: "vex", Status: "not_affected", Justification: "vulnerable_code_not_present"}
	}
	active := sampleFinding("CVE-2026-0001", "HIGH", 0.7)
	findings = append(findings, active)

	got := Build(dedupeInventory(), findings, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Dedupe: true})

	if len(got.SuppressedFindings) != 1 {
		t.Fatalf("SuppressedFindings len = %d, want 1 merged entry: %#v", len(got.SuppressedFindings), got.SuppressedFindings)
	}
	suppressed := got.SuppressedFindings[0]
	if len(suppressed.Affected) != 2 {
		t.Fatalf("suppressed Affected = %#v, want union of both refs", suppressed.Affected)
	}
	if suppressed.WouldHaveBeenPain == nil || suppressed.WouldHaveBeenRemediation == nil {
		t.Fatalf("suppressed would-have-been = %#v/%#v, want populated", suppressed.WouldHaveBeenPain, suppressed.WouldHaveBeenRemediation)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("Findings len = %d, want active copy kept separate from suppressed: %#v", len(got.Findings), got.Findings)
	}
}
