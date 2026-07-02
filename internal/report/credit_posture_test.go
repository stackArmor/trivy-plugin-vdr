package report

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/controlcredit"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

// cc4Taxonomy loads the CC4 report test fixture (a firing impact row, a blocked
// near-miss row, and a firing likelihood row).
func cc4Taxonomy(t *testing.T) *controlcredit.Taxonomy {
	t.Helper()
	tax, err := controlcredit.Load(context.Background(), "testdata/cc4-taxonomy")
	if err != nil || !tax.Enabled {
		t.Fatalf("load cc4 fixture taxonomy: %v (enabled=%v)", err, tax.Enabled)
	}
	return tax
}

// cc4Inventory is a single Deployment whose workload facts satisfy the
// egress-default-deny control, so the impact and likelihood rows keyed on it fire.
func cc4Inventory() *model.Inventory {
	inv := sampleInventory()
	inv.Resources[0].Facts = &model.WorkloadFacts{EgressDefaultDeny: true}
	return inv
}

// cc4Findings returns an SSRF finding (CWE-918, fires the egress + EDR rows) and a
// command-injection finding (CWE-78, near-miss on the never-verified no-shell row).
func cc4Findings() []model.Finding {
	ssrf := sampleFinding("CVE-2026-9001", "HIGH", 0.9)
	ssrf.CWEs = []string{"CWE-918"}
	ssrf.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	ssrf.Vulnrichment = &model.Vulnrichment{Exploitation: "none"} // not KEV, so EPSS may be lowered

	cmdi := sampleFinding("CVE-2026-9002", "HIGH", 0.4)
	cmdi.CWEs = []string{"CWE-78"}
	cmdi.CVSSVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	cmdi.Vulnrichment = &model.Vulnrichment{Exploitation: "none"}
	return []model.Finding{ssrf, cmdi}
}

// TestCreditPostureFiringAndBlocked proves the CC4 credit-posture report carries,
// per workload, the firing rows with affected-finding counts and the near-miss
// rows with the exact failed predicate and benefiting-finding count.
func TestCreditPostureFiringAndBlocked(t *testing.T) {
	tax := cc4Taxonomy(t)
	got := Build(cc4Inventory(), cc4Findings(), nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Taxonomy: tax, TaxonomyLabel: "full-v0.9.0"})

	if len(got.CreditPosture) != 1 {
		t.Fatalf("creditPosture entries = %d, want 1: %+v", len(got.CreditPosture), got.CreditPosture)
	}
	posture := got.CreditPosture[0]
	if posture.Resource.ContainerName != "" {
		t.Fatalf("posture should be reported at the workload level, got container %q", posture.Resource.ContainerName)
	}

	var egress *model.CreditFiring
	for i := range posture.Firing {
		if posture.Firing[i].RowID == "CC-TEST-EGRESS" {
			egress = &posture.Firing[i]
		}
	}
	if egress == nil {
		t.Fatalf("firing rows missing CC-TEST-EGRESS: %+v", posture.Firing)
	}
	if egress.Findings != 1 {
		t.Fatalf("CC-TEST-EGRESS firing findings = %d, want 1", egress.Findings)
	}

	var noshell *model.CreditBlocked
	for i := range posture.Blocked {
		if posture.Blocked[i].RowID == "CC-TEST-NOSHELL" {
			noshell = &posture.Blocked[i]
		}
	}
	if noshell == nil {
		t.Fatalf("blocked rows missing CC-TEST-NOSHELL: %+v", posture.Blocked)
	}
	if noshell.Findings != 1 {
		t.Fatalf("CC-TEST-NOSHELL benefiting findings = %d, want 1", noshell.Findings)
	}
	if !strings.Contains(noshell.FailedPredicate, "no-shell-image") || noshell.FailedPredicate == "" {
		t.Fatalf("blocked row must carry the exact failed predicate, got %q", noshell.FailedPredicate)
	}

	// Legend maps referenced row ids to their short titles.
	if got.CreditLegend["CC-TEST-EGRESS"] == "" || got.CreditLegend["CC-TEST-NOSHELL"] == "" {
		t.Fatalf("credit legend missing titles: %+v", got.CreditLegend)
	}

	// The near-miss predicate and count survive JSON serialization.
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"failedPredicate"`, "no-shell-image", `"creditPosture"`, `"creditLegend"`} {
		if !strings.Contains(string(blob), want) {
			t.Fatalf("credit-posture JSON missing %q", want)
		}
	}
}

// TestCreditPaintDowngradeAndAdjustedEPSS proves a firing impact credit lowers the
// finding's PAIN (recorded as UncreditedTier) and a firing likelihood credit lowers
// adjustedEPSS below the threshold, flipping LEV.
func TestCreditPaintDowngradeAndAdjustedEPSS(t *testing.T) {
	tax := cc4Taxonomy(t)
	got := Build(cc4Inventory(), cc4Findings(), nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Taxonomy: tax, TaxonomyLabel: "full-v0.9.0"})

	var ssrf *model.Finding
	for i := range got.Findings {
		if got.Findings[i].ID == "CVE-2026-9001" {
			ssrf = &got.Findings[i]
		}
	}
	if ssrf == nil {
		t.Fatalf("SSRF finding not found in report")
	}
	if ssrf.Pain == nil || ssrf.Pain.UncreditedTier == "" {
		t.Fatalf("expected a PAIN downgrade recorded, got %+v", ssrf.Pain)
	}
	if ssrf.Pain.UncreditedTier == ssrf.Pain.Tier {
		t.Fatalf("uncredited tier %q should differ from credited tier %q", ssrf.Pain.UncreditedTier, ssrf.Pain.Tier)
	}
	if ssrf.Exploitability == nil {
		t.Fatalf("expected exploitability adjustment")
	}
	if !(ssrf.Exploitability.AdjustedEPSS < ssrf.Exploitability.EPSS) {
		t.Fatalf("adjustedEPSS %v should be below published EPSS %v", ssrf.Exploitability.AdjustedEPSS, ssrf.Exploitability.EPSS)
	}
	if ssrf.Exploitability.EPSS != 0.9 {
		t.Fatalf("published EPSS mutated: %v", ssrf.Exploitability.EPSS)
	}
	if !ssrf.Exploitability.LoweredLEV {
		t.Fatalf("expected LEV to be lowered by the adjustment")
	}
}

// TestHTMLCreditSurfacingWhenTaxonomyOn proves the HTML renders the credit
// adjustments (PAIN downgrade, adjustedEPSS), the per-workload posture, and the
// row-id legend when a taxonomy is loaded.
func TestHTMLCreditSurfacingWhenTaxonomyOn(t *testing.T) {
	tax := cc4Taxonomy(t)
	got := Build(cc4Inventory(), cc4Findings(), nil, Options{GeneratedAt: fixedTime(), View: ViewResources, Taxonomy: tax, TaxonomyLabel: "full-v0.9.0"})
	var buf bytes.Buffer
	if err := RenderHTML(&buf, got, ""); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Control-credit adjustments",
		"Control-credit posture",
		"Control-credit key",
		"CC-TEST-EGRESS",
		"CC-TEST-NOSHELL",
		"one predicate away",
		"uncreditedTier",                           // PAIN downgrade data carried in report JSON
		"loweredLev",                               // LEV-moved data carried in report JSON
		"Egress lockdown bounds SSRF blast radius", // legend title
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML with taxonomy missing %q", want)
		}
	}
}

// TestHTMLNoTaxonomyByteIdentical proves the HTML output is byte-identical with no
// taxonomy vs an explicitly disabled taxonomy, and carries none of the credit UI.
func TestHTMLNoTaxonomyByteIdentical(t *testing.T) {
	inv := cc4Inventory()
	findings := cc4Findings()

	none := Build(inv, findings, nil, Options{GeneratedAt: fixedTime(), View: ViewResources})
	disabled := Build(inv, findings, nil, Options{GeneratedAt: fixedTime(), View: ViewResources, Taxonomy: controlcredit.Disabled()})

	var noneBuf, disabledBuf bytes.Buffer
	if err := RenderHTML(&noneBuf, none, ""); err != nil {
		t.Fatalf("RenderHTML none: %v", err)
	}
	if err := RenderHTML(&disabledBuf, disabled, ""); err != nil {
		t.Fatalf("RenderHTML disabled: %v", err)
	}
	if !bytes.Equal(noneBuf.Bytes(), disabledBuf.Bytes()) {
		t.Fatalf("no-taxonomy vs disabled-taxonomy HTML diverged")
	}
	if strings.Contains(noneBuf.String(), "Control-credit") || strings.Contains(noneBuf.String(), "creditPosture") {
		t.Fatalf("no-taxonomy HTML leaked control-credit UI")
	}
}

// TestTableCreditPostureSection proves the compact posture section appears in the
// table output when a taxonomy is loaded, with firing counts and the near-miss
// predicate + benefiting-finding count.
func TestTableCreditPostureSection(t *testing.T) {
	tax := cc4Taxonomy(t)
	got := Build(cc4Inventory(), cc4Findings(), nil, Options{GeneratedAt: fixedTime(), View: ViewFindings, Taxonomy: tax, TaxonomyLabel: "full-v0.9.0"})
	var buf bytes.Buffer
	if err := RenderTable(&buf, got); err != nil {
		t.Fatalf("RenderTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"CONTROL-CREDIT POSTURE",
		"CC-TEST-EGRESS (1)",
		"CC-TEST-NOSHELL",
		"1 findings",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("table posture section missing %q:\n%s", want, out)
		}
	}
}
