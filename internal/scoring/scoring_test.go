package scoring

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

const (
	vecCIAHigh = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // RCE
	vecInfoLow = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" // info-leak
	vecDoSHigh = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" // availability DoS
	vecConfHi  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" // confidentiality
)

// TestWorkedExamples reproduces the six worked examples published in the VDR
// Confluence strategy page (PAIN expected N5/N3/N2/N5/N4/N5).
func TestWorkedExamples(t *testing.T) {
	cfg := Default()
	// The amplifier example (#4) assumes the offering serves more than one agency.
	cfg.CSOServesMultipleAgencies = true

	cases := []struct {
		name     string
		in       Input
		wantS    float64
		wantWord string
		wantTier string
	}{
		{
			name:  "1 RCE on data-sensitive multi",
			in:    Input{CVSSVector: vecCIAHigh, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "data-sensitive", "vdr.fedramp.io/multi-agency": "true"}},
			wantS: 1.00, wantWord: "Debilitating", wantTier: "N5",
		},
		{
			name:  "2 same RCE on dev-test single",
			in:    Input{CVSSVector: vecCIAHigh, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "dev-test", "vdr.fedramp.io/multi-agency": "false"}},
			wantS: 0.69, wantWord: "Disruptive", wantTier: "N3",
		},
		{
			name:  "3 info-leak on data-sensitive multi",
			in:    Input{CVSSVector: vecInfoLow, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "data-sensitive", "vdr.fedramp.io/multi-agency": "true"}},
			wantS: 0.36, wantWord: "Narrow", wantTier: "N2",
		},
		{
			name:  "4 RCE on cicd-pipeline amplifier single",
			in:    Input{CVSSVector: vecCIAHigh, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "cicd-pipeline", "vdr.fedramp.io/multi-agency": "false"}},
			wantS: 1.00, wantWord: "Debilitating", wantTier: "N5",
		},
		{
			name:  "5 DoS on public-edge single",
			in:    Input{CVSSVector: vecDoSHigh, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "public-edge", "vdr.fedramp.io/multi-agency": "false"}},
			wantS: 0.92, wantWord: "Debilitating", wantTier: "N4",
		},
		{
			// Untagged now resolves to the built-in H/H/H "unclassified" default
			// (single-agency), so a confidentiality-only High lands at N4 rather than
			// the old forced-multi N5 fail-safe (see TestFailSafeForcesN5WhenNoDefault).
			name:  "6 confidentiality on untagged (built-in default)",
			in:    Input{CVSSVector: vecConfHi},
			wantS: 0.92, wantWord: "Debilitating", wantTier: "N4",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cfg.Score(tc.in)
			if got.Tier != tc.wantTier {
				t.Errorf("Tier = %s, want %s", got.Tier, tc.wantTier)
			}
			if got.Word != tc.wantWord {
				t.Errorf("Word = %s, want %s", got.Word, tc.wantWord)
			}
			if math.Abs(got.Severity-tc.wantS) > 0.01 {
				t.Errorf("Severity = %.4f, want ~%.2f", got.Severity, tc.wantS)
			}
		})
	}
}

func TestBuiltInDefaultArchetype(t *testing.T) {
	cfg := Default() // single-tenant default (multiAgency=false)
	// Untagged resources resolve to the built-in H/H/H "unclassified" archetype:
	// noisy (single-agency H/H/H + C:H/I:H/A:H => N4) but not the forced-multi N5.
	got := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "weird", WorkloadName: "mystery"})
	if got.ArchetypeSource != "default" || got.Archetype != "unclassified" {
		t.Errorf("source=%s archetype=%s, want default/unclassified", got.ArchetypeSource, got.Archetype)
	}
	if got.Tier != "N4" {
		t.Errorf("untagged Tier = %s, want N4 (noisy default, not forced-multi N5)", got.Tier)
	}
	if got.MultiAgency {
		t.Error("built-in default archetype must not force multi-agency")
	}
}

func TestFailSafeForcesN5WhenNoDefault(t *testing.T) {
	cfg := Default()
	cfg.Defaults.Archetype = "" // clear the default => true fail-safe takes over
	got := cfg.Score(Input{CVSSVector: vecConfHi, Namespace: "weird", WorkloadName: "mystery"})
	if got.Tier != "N5" {
		t.Errorf("untagged Tier = %s, want N5 (fail-safe must force multi-agency)", got.Tier)
	}
	if got.ArchetypeSource != "failsafe" {
		t.Errorf("ArchetypeSource = %s, want failsafe", got.ArchetypeSource)
	}
}

func TestSingleTenantAmplifierDoesNotFloorN5(t *testing.T) {
	cfg := Default() // CSOServesMultipleAgencies=false (single-tenant)
	// cicd-pipeline is an amplifier, but single-tenant => amplifier inert.
	got := cfg.Score(Input{CVSSVector: vecCIAHigh, Labels: map[string]string{
		"vdr.fedramp.io/asset-archetype": "cicd-pipeline",
		"vdr.fedramp.io/multi-agency":    "false",
	}})
	if got.Tier != "N4" {
		t.Errorf("Tier = %s, want N4 (single-tenant amplifier must not reach N5)", got.Tier)
	}
}

func TestResolutionOrder(t *testing.T) {
	cfg := Default()
	cfg.NameRules = []NameRule{{Namespace: "kube-system", Match: "calico*", Archetype: "orchestrator"}}
	cfg.NamespaceRules = []NamespaceRule{{Match: "kube-system", Archetype: "internal-tooling"}}

	// Label wins over everything.
	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "calico-node",
		Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "app-tier"}})
	if r.ArchetypeSource != "label" || r.Archetype != "app-tier" {
		t.Errorf("label precedence failed: source=%s archetype=%s", r.ArchetypeSource, r.Archetype)
	}

	// Name rule wins over namespace rule.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "calico-node"})
	if r.ArchetypeSource != "nameRule" || r.Archetype != "orchestrator" {
		t.Errorf("nameRule precedence failed: source=%s archetype=%s", r.ArchetypeSource, r.Archetype)
	}

	// Namespace rule when no name rule matches.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "metrics-server"})
	if r.ArchetypeSource != "namespaceRule" || r.Archetype != "internal-tooling" {
		t.Errorf("namespaceRule fallback failed: source=%s archetype=%s", r.ArchetypeSource, r.Archetype)
	}

	// Nothing matches => built-in cluster-default archetype.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "other", WorkloadName: "thing"})
	if r.ArchetypeSource != "default" || r.Archetype != "unclassified" {
		t.Errorf("expected default/unclassified, got source=%s archetype=%s", r.ArchetypeSource, r.Archetype)
	}
}

// TestManagedNamespaceNoFalseN5 confirms that a managed-namespace workload
// classified by a namespace rule is scored on its merits (not floored to N5).
func TestManagedNamespaceNoFalseN5(t *testing.T) {
	cfg := Default()
	cfg.NamespaceRules = []NamespaceRule{{Match: "kube-system", Archetype: "internal-tooling"}}
	got := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "metrics-server-v1"})
	if got.Tier == "N5" {
		t.Errorf("managed-ns workload floored to N5; expected lower (got source=%s)", got.ArchetypeSource)
	}
	if got.ArchetypeSource != "namespaceRule" {
		t.Errorf("ArchetypeSource = %s, want namespaceRule", got.ArchetypeSource)
	}
}

func TestLoadDeepMerges(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "vdr-scoring.yaml")
	body := `
defaults:
  multiAgency: false
namespaceRules:
  - match: kube-system
    archetype: internal-tooling
nameRules:
  - namespace: kube-system
    match: "gke-metadata-server"
    archetype: identity-secrets
`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(file)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Built-in catalog survives the merge.
	if _, ok := cfg.Archetypes["data-backbone"]; !ok {
		t.Error("expected built-in archetype catalog to survive merge")
	}
	// Label keys default survives.
	if cfg.LabelKeys.Archetype != "vdr.fedramp.io/asset-archetype" {
		t.Errorf("LabelKeys.Archetype = %s, want default", cfg.LabelKeys.Archetype)
	}
	// File rules are applied.
	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "gke-metadata-server"})
	if r.Archetype != "identity-secrets" {
		t.Errorf("Archetype = %s, want identity-secrets from nameRule", r.Archetype)
	}
}

func TestTechnicalImpactFloor(t *testing.T) {
	weakRCE := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"

	// total lifts every in-scope Low dimension to High.
	c, i, a, src := impact("total", weakRCE, "")
	if c != 0.56 || i != 0.56 || a != 0.56 {
		t.Errorf("weak RCE + total = %v/%v/%v, want all High", c, i, a)
	}
	if src != "cvss+technicalImpact" {
		t.Errorf("source = %q, want cvss+technicalImpact", src)
	}

	// total never invents impact on None dimensions (info-leak stays conf-only),
	// and since nothing was lifted (C already High) technical impact is not credited.
	c, i, a, src = impact("total", vecConfHi, "")
	if c != 0.56 || i != 0 || a != 0 {
		t.Errorf("info-leak + total = %v/%v/%v, want C-only High", c, i, a)
	}
	if src != "cvss" {
		t.Errorf("source = %q, want cvss (nothing lifted)", src)
	}

	// partial and absent leave the vector unchanged.
	if c, i, a, src = impact("partial", weakRCE, ""); c != 0.22 || i != 0.22 || a != 0.22 || src != "cvss" {
		t.Errorf("partial changed the vector: %v/%v/%v src=%q", c, i, a, src)
	}
	if c, i, a, src = impact("", vecConfHi, ""); c != 0.56 || i != 0 || a != 0 || src != "cvss" {
		t.Errorf("absent TI changed the vector: %v/%v/%v src=%q", c, i, a, src)
	}
}

func TestTechnicalImpactRaisesTier(t *testing.T) {
	cfg := Default()
	weakRCE := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
	base := Input{CVSSVector: weakRCE, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "data-sensitive"}}

	if got := cfg.Score(base).Tier; got != "N3" {
		t.Fatalf("baseline Tier = %s, want N3 (precondition)", got)
	}
	withTI := base
	withTI.TechnicalImpact = "total"
	r := cfg.Score(withTI)
	if r.Tier != "N4" {
		t.Errorf("with TI=total Tier = %s, want N4 (floor lifts L->H)", r.Tier)
	}
	if r.SeveritySource != "cvss+technicalImpact" {
		t.Errorf("SeveritySource = %q, want cvss+technicalImpact", r.SeveritySource)
	}
}

func TestDefaultArchetypeFallback(t *testing.T) {
	cfg := Default()
	// A noisy H/H/H cluster default archetype catches new/unclassified resources.
	cfg.Archetypes["cluster-default"] = Archetype{Lens: "control", CR: "H", IR: "H", AR: "H"}
	cfg.Defaults.Archetype = "cluster-default"

	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "new-ns", WorkloadName: "thing"})
	if r.ArchetypeSource != "default" || r.Archetype != "cluster-default" {
		t.Fatalf("source=%s archetype=%s, want default/cluster-default", r.ArchetypeSource, r.Archetype)
	}
	// H/H/H + C:H/I:H/A:H but single-agency (not forced multi) => N4, not the N5 fail-safe.
	if r.Tier != "N4" {
		t.Errorf("Tier = %s, want N4 (default archetype must not force multi-agency)", r.Tier)
	}
	if r.MultiAgency {
		t.Error("default archetype must not force multi-agency")
	}
}

func TestApplyClusterDefaultsEmbeddedDoc(t *testing.T) {
	cfg := Default()
	data := map[string]string{
		"class": "C",
		"scoring.yaml": `
archetypes:
  cluster-default: {lens: control, cr: H, ir: H, ar: H}
defaults:
  archetype: cluster-default
nameRules:
  - {namespace: rally, match: postgres, archetype: data-backbone}
namespaceRules:
  - {match: kube-system, archetype: internal-tooling}
`,
	}
	if err := cfg.ApplyClusterDefaults(data); err != nil {
		t.Fatalf("ApplyClusterDefaults: %v", err)
	}
	if cfg.Defaults.Class != "C" {
		t.Errorf("Class = %s, want C (scalar override)", cfg.Defaults.Class)
	}
	if cfg.Defaults.Archetype != "cluster-default" {
		t.Errorf("default archetype = %s, want cluster-default (from embedded doc)", cfg.Defaults.Archetype)
	}
	if r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "postgres"}); r.Archetype != "data-backbone" || r.ArchetypeSource != "nameRule" {
		t.Errorf("embedded nameRule not applied: %s/%s", r.Archetype, r.ArchetypeSource)
	}
	if _, ok := cfg.Archetypes["data-sensitive"]; !ok {
		t.Error("built-in archetype catalog should survive ConfigMap merge")
	}

	// An embedded doc referencing an unknown archetype is rejected.
	bad := Default()
	if err := bad.ApplyClusterDefaults(map[string]string{"scoring": "namespaceRules:\n  - {match: x, archetype: nope}\n"}); err == nil {
		t.Error("expected validate error for unknown archetype in ConfigMap doc")
	}
}

func TestPlatformFoundationArchetype(t *testing.T) {
	cfg := Default()
	a, ok := cfg.Archetypes["platform-foundation"]
	if !ok {
		t.Fatal("platform-foundation archetype missing from built-in catalog")
	}
	if a.CR != "L" || a.IR != "H" || a.AR != "H" || !a.Amplifier {
		t.Errorf("platform-foundation = %+v, want CR:L IR:H AR:H amplifier:true", a)
	}
	lbl := map[string]string{"vdr.fedramp.io/asset-archetype": "platform-foundation"}
	// Availability DoS (A:H) => N4 single-agency (DNS outage is debilitating).
	if got := cfg.Score(Input{CVSSVector: vecDoSHigh, Labels: lbl}).Tier; got != "N4" {
		t.Errorf("A:H DoS Tier = %s, want N4", got)
	}
	// Confidentiality-only High (C:H) => N2 (metadata recon only, CR:L).
	if got := cfg.Score(Input{CVSSVector: vecConfHi, Labels: lbl}).Tier; got != "N2" {
		t.Errorf("C:H Tier = %s, want N2 (CR:L)", got)
	}
}

func TestWordThresholds(t *testing.T) {
	cfg := Default()
	cases := []struct {
		s    float64
		want string
	}{
		{0.24, "Minimal"}, {0.25, "Narrow"}, {0.54, "Narrow"}, {0.55, "Disruptive"},
		{0.80, "Disruptive"}, {0.84, "Disruptive"}, {0.85, "Debilitating"}, {1.0, "Debilitating"},
	}
	for _, c := range cases {
		if got := cfg.wordFromScalar(c.s); got != c.want {
			t.Errorf("wordFromScalar(%.2f) = %s, want %s", c.s, got, c.want)
		}
	}
	// Zero-value config falls back to the built-in thresholds (never all-Debilitating).
	if got := (&Config{}).wordFromScalar(0.5); got != "Narrow" {
		t.Errorf("zero-value config wordFromScalar(0.5) = %s, want Narrow (fallback)", got)
	}
}

func TestConfigurableWordThresholds(t *testing.T) {
	// Override only the Debilitating bar; the rest keep their defaults.
	cfg := Default()
	cfg.WordThresholds.Debilitating = 0.95
	if got := cfg.wordFromScalar(0.90); got != "Disruptive" {
		t.Errorf("with Debilitating=0.95, S=0.90 = %s, want Disruptive", got)
	}
	if got := cfg.wordFromScalar(0.96); got != "Debilitating" {
		t.Errorf("with Debilitating=0.95, S=0.96 = %s, want Debilitating", got)
	}

	// Loaded from a config file (partial override merges over defaults).
	dir := t.TempDir()
	file := filepath.Join(dir, "t.yaml")
	if err := os.WriteFile(file, []byte("wordThresholds:\n  debilitating: 0.90\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(file)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.WordThresholds.Narrow != 0.25 || loaded.WordThresholds.Disruptive != 0.55 || loaded.WordThresholds.Debilitating != 0.90 {
		t.Errorf("merged thresholds = %+v, want narrow=0.25 disruptive=0.55 debilitating=0.90", loaded.WordThresholds)
	}

	// Non-ascending thresholds are rejected.
	bad := Default()
	bad.WordThresholds = WordThresholds{Narrow: 0.6, Disruptive: 0.5, Debilitating: 0.85}
	if err := bad.validate(); err == nil {
		t.Error("expected error for non-ascending wordThresholds")
	}
}

func TestValidateRejectsUnknownDefaultArchetype(t *testing.T) {
	cfg := Default()
	cfg.Defaults.Archetype = "does-not-exist"
	if err := cfg.validate(); err == nil {
		t.Error("expected error for unknown defaults.archetype")
	}
	// The built-in default ("unclassified") is in the catalog, so it validates.
	if err := Default().validate(); err != nil {
		t.Errorf("built-in Default() should validate: %v", err)
	}
}

func TestLoadRejectsUnknownArchetype(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(file, []byte("namespaceRules:\n  - match: foo\n    archetype: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file); err == nil {
		t.Error("expected error for unknown archetype in rule")
	}
}
