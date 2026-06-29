package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scoring"
)

const vecCIAHigh = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

func labeledInventory(ns, name, archetype string) (*model.Inventory, model.ResourceRef) {
	workload := model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: ns, Name: name}
	container := workload
	container.ContainerName = "app"
	container.ContainerType = "container"
	labels := map[string]string{}
	if archetype != "" {
		labels["vdr.fedramp.io/asset-archetype"] = archetype
	}
	inv := &model.Inventory{
		ContextName: "test",
		Resources: []model.ResourceInventory{{
			Resource: workload,
			Labels:   labels,
			Images:   []model.ContainerImage{{Name: "app", ContainerType: "container", ImageRef: "example/app:v1"}},
		}},
		Images: []model.ImageInventory{{ImageRef: "example/app:v1", Resources: []model.ResourceRef{container}}},
	}
	return inv, container
}

func painFinding(id string, refs ...model.ResourceRef) model.Finding {
	return model.Finding{
		ID:                id,
		ImageRef:          "example/app:v1",
		Severity:          "HIGH",
		CVSSVector:        vecCIAHigh,
		EPSS:              &model.EPSS{Score: 0.5},
		AffectedResources: refs,
	}
}

func TestBuildAssignsPainFromLabel(t *testing.T) {
	inv, ref := labeledInventory("apps", "report-svc", "dev-test")
	finding := painFinding("CVE-2026-1000", ref)

	got := Build(inv, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings})
	if len(got.Findings) != 1 || got.Findings[0].Pain == nil {
		t.Fatalf("expected one finding with PAIN, got %#v", got.Findings)
	}
	// dev-test (L/L/L) with a C:H/I:H/A:H impact => Disruptive, single-agency => N3.
	if got.Findings[0].Pain.Tier != "N3" {
		t.Errorf("Tier = %s, want N3", got.Findings[0].Pain.Tier)
	}
	if got.Findings[0].Pain.ArchetypeSource != "label" {
		t.Errorf("ArchetypeSource = %s, want label", got.Findings[0].Pain.ArchetypeSource)
	}

	// Resources view scopes PAIN to the single resource as well.
	res := Build(inv, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	if len(res.Resources) != 1 || len(res.Resources[0].Findings) != 1 || res.Resources[0].Findings[0].Pain == nil {
		t.Fatalf("expected scoped finding with PAIN in resources view, got %#v", res.Resources)
	}
	if res.Resources[0].Findings[0].Pain.Tier != "N3" {
		t.Errorf("resource-view Tier = %s, want N3", res.Resources[0].Findings[0].Pain.Tier)
	}
}

func TestBuildPainWorstAcrossAffected(t *testing.T) {
	// One finding affects an app-tier asset (=> N4) and a dev-test asset (=> N3);
	// the finding-level PAIN must be the worst (N4).
	appWorkload := model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "apps", Name: "api"}
	appRef := appWorkload
	appRef.ContainerName = "app"
	appRef.ContainerType = "container"
	devWorkload := model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "apps", Name: "sandbox"}
	devRef := devWorkload
	devRef.ContainerName = "app"
	devRef.ContainerType = "container"

	inv := &model.Inventory{
		Resources: []model.ResourceInventory{
			{Resource: appWorkload, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "app-tier"}, Images: []model.ContainerImage{{Name: "app", ContainerType: "container", ImageRef: "example/app:v1"}}},
			{Resource: devWorkload, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "dev-test"}, Images: []model.ContainerImage{{Name: "app", ContainerType: "container", ImageRef: "example/app:v1"}}},
		},
		Images: []model.ImageInventory{{ImageRef: "example/app:v1", Resources: []model.ResourceRef{appRef, devRef}}},
	}
	finding := painFinding("CVE-2026-2000", appRef, devRef)

	got := Build(inv, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings})
	if len(got.Findings) != 1 || got.Findings[0].Pain == nil {
		t.Fatalf("expected one finding with PAIN, got %#v", got.Findings)
	}
	if got.Findings[0].Pain.Tier != "N4" {
		t.Errorf("worst PAIN = %s, want N4", got.Findings[0].Pain.Tier)
	}
	if len(got.Findings[0].Affected) != 2 {
		t.Fatalf("expected 2 affected entries with per-asset PAIN, got %#v", got.Findings[0].Affected)
	}
}

func TestBuildComputesRemediation(t *testing.T) {
	inv, ref := labeledInventory("apps", "db", "data-sensitive")
	inv.Resources[0].Labels["vdr.fedramp.io/multi-agency"] = "true"
	finding := painFinding("CVE-2026-6000", ref)
	finding.EPSS = &model.EPSS{Score: 0.9} // LEV
	finding.Vulnrichment = &model.Vulnrichment{Exploitation: "active"}
	exposures := map[model.ResourceRef]model.Exposure{ref: {InternetAccessible: true}} // IRV

	sc := scoring.Default()
	sc.Defaults.Class = "C"

	got := Build(inv, []model.Finding{finding}, exposures, Options{GeneratedAt: fixedTime(), View: ViewFindings, Scoring: sc})
	if len(got.Findings) != 1 || got.Findings[0].Remediation == nil {
		t.Fatalf("expected finding with remediation, got %#v", got.Findings)
	}
	rem := got.Findings[0].Remediation
	// data-sensitive + multi + C:H/I:H/A:H => N5; LEV + IRV; Class C => 2 days.
	if got.Findings[0].Pain.Tier != "N5" {
		t.Fatalf("Tier = %s, want N5", got.Findings[0].Pain.Tier)
	}
	if rem.Class != "C" || rem.Column != "LEV+IRV" || rem.DeadlineDays != 2 || rem.Deadline != "2 days" {
		t.Errorf("remediation = %+v, want Class C / LEV+IRV / 2 days", rem)
	}
}

func TestBuildCloudRunResourceLabelsOverrideProjectLabels(t *testing.T) {
	workload := model.ResourceRef{
		APIVersion: "run.googleapis.com/v1",
		Kind:       "Service",
		Provider:   "gcp-cloud-run",
		Project:    "p",
		Region:     "us-east4",
		Name:       "api",
	}
	container := workload
	container.ContainerName = "app"
	container.ContainerType = "container"
	inv := &model.Inventory{
		ContextName: "cloudrun/p",
		Namespaces: map[string]map[string]string{
			"cloudrun/p": {
				"vdr.fedramp.io/asset-archetype": "data-sensitive",
				"vdr.fedramp.io/multi-agency":    "true",
				"vdr.fedramp.io/class":           "D",
			},
		},
		Resources: []model.ResourceInventory{{
			Resource: workload,
			Labels: map[string]string{
				"vdr.fedramp.io/asset-archetype": "dev-test",
				"vdr.fedramp.io/multi-agency":    "false",
				"vdr.fedramp.io/class":           "B",
			},
			Images: []model.ContainerImage{{Name: "app", ContainerType: "container", ImageRef: "example/app:v1"}},
		}},
		Images: []model.ImageInventory{{ImageRef: "example/app:v1", Resources: []model.ResourceRef{container}}},
	}
	finding := painFinding("CVE-2026-7000", container)
	finding.EPSS = &model.EPSS{Score: 0.9}

	got := Build(inv, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	if len(got.Resources) != 1 || len(got.Resources[0].Findings) != 1 {
		t.Fatalf("expected one Cloud Run resource finding, got %#v", got.Resources)
	}
	pain := got.Resources[0].Findings[0].Pain
	rem := got.Resources[0].Findings[0].Remediation
	if pain == nil || rem == nil {
		t.Fatalf("expected PAIN/remediation, got pain=%#v remediation=%#v", pain, rem)
	}
	if pain.Archetype != "dev-test" || pain.ArchetypeSource != "label" || pain.MultiAgency {
		t.Fatalf("PAIN = %#v, want resource labels dev-test/single-agency", pain)
	}
	if rem.Class != "B" {
		t.Fatalf("remediation class = %q, want resource label class B", rem.Class)
	}
}

func TestBuildCloudRunUsesProjectLabelsAsFallback(t *testing.T) {
	workload := model.ResourceRef{
		APIVersion: "run.googleapis.com/v1",
		Kind:       "Job",
		Provider:   "gcp-cloud-run",
		Project:    "p",
		Region:     "us-east4",
		Name:       "batch",
	}
	container := workload
	container.ContainerName = "worker"
	container.ContainerType = "container"
	inv := &model.Inventory{
		ContextName: "cloudrun/p",
		Namespaces: map[string]map[string]string{
			"cloudrun/p": {
				"vdr.fedramp.io/asset-archetype": "data-sensitive",
				"vdr.fedramp.io/multi-agency":    "true",
				"vdr.fedramp.io/class":           "D",
			},
		},
		Resources: []model.ResourceInventory{{
			Resource: workload,
			Images:   []model.ContainerImage{{Name: "worker", ContainerType: "container", ImageRef: "example/app:v1"}},
		}},
		Images: []model.ImageInventory{{ImageRef: "example/app:v1", Resources: []model.ResourceRef{container}}},
	}
	finding := painFinding("CVE-2026-7001", container)
	finding.EPSS = &model.EPSS{Score: 0.9}

	got := Build(inv, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	if len(got.Resources) != 1 || len(got.Resources[0].Findings) != 1 {
		t.Fatalf("expected one Cloud Run resource finding, got %#v", got.Resources)
	}
	pain := got.Resources[0].Findings[0].Pain
	rem := got.Resources[0].Findings[0].Remediation
	if pain == nil || rem == nil {
		t.Fatalf("expected PAIN/remediation, got pain=%#v remediation=%#v", pain, rem)
	}
	if pain.Archetype != "data-sensitive" || pain.ArchetypeSource != "namespaceLabel" || !pain.MultiAgency {
		t.Fatalf("PAIN = %#v, want project fallback labels data-sensitive/multi-agency", pain)
	}
	if rem.Class != "D" {
		t.Fatalf("remediation class = %q, want project fallback class D", rem.Class)
	}
}

func TestBuildManagedNamespaceRuleNoFalseN5(t *testing.T) {
	inv, ref := labeledInventory("kube-system", "metrics-server-v1", "") // no label
	finding := painFinding("CVE-2026-3000", ref)
	finding.Severity = "HIGH"

	sc := scoring.Default()
	sc.NamespaceRules = []scoring.NamespaceRule{{Match: "kube-system", Archetype: "internal-tooling"}}

	got := Build(inv, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Scoring: sc})
	if len(got.Findings) != 1 || got.Findings[0].Pain == nil {
		t.Fatalf("expected one finding with PAIN, got %#v", got.Findings)
	}
	if got.Findings[0].Pain.Tier == "N5" {
		t.Errorf("managed-ns workload floored to N5; want lower (source=%s)", got.Findings[0].Pain.ArchetypeSource)
	}
	if got.Findings[0].Pain.ArchetypeSource != "namespaceRule" {
		t.Errorf("ArchetypeSource = %s, want namespaceRule", got.Findings[0].Pain.ArchetypeSource)
	}
}

func TestRenderHTMLIncludesPainColumnAndData(t *testing.T) {
	inv, ref := labeledInventory("apps", "svc", "dev-test")
	finding := painFinding("CVE-2026-5000", ref)
	rep := Build(inv, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})

	var buf bytes.Buffer
	if err := RenderHTML(&buf, rep, ""); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<th>PAIN</th>") {
		t.Error("HTML missing PAIN column header")
	}
	if !strings.Contains(out, "\"tier\":\"N3\"") {
		t.Error("HTML missing serialized PAIN data")
	}
	// dev-test N3, no LEV, no IRV => NLEV, Class B => 192 days.
	if !strings.Contains(out, "\"deadline\":\"192 days\"") {
		t.Error("HTML missing serialized FedRAMP remediation deadline")
	}
}

func TestBuildUntaggedUsesDefaultArchetype(t *testing.T) {
	inv, ref := labeledInventory("random", "mystery", "") // no label, no rule
	finding := painFinding("CVE-2026-4000", ref)

	got := Build(inv, []model.Finding{finding}, nil, Options{GeneratedAt: fixedTime(), View: ViewFindings})
	// Built-in cluster-default archetype (H/H/H) + C:H/I:H/A:H, single-agency => N4.
	if got.Findings[0].Pain.Tier != "N4" {
		t.Errorf("untagged Tier = %s, want N4 (built-in default archetype)", got.Findings[0].Pain.Tier)
	}
	if got.Findings[0].Pain.ArchetypeSource != "default" {
		t.Errorf("ArchetypeSource = %s, want default", got.Findings[0].Pain.ArchetypeSource)
	}
}
