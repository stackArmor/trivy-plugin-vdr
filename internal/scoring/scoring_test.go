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

// TestWorkedExamples reproduces the worked examples published in the PAIN
// methodology (PAIN expected N5/N3/N2/N5/N3/N3).
func TestWorkedExamples(t *testing.T) {
	cfg := Default()

	cases := []struct {
		name     string
		in       Input
		wantS    float64
		wantWord string
		wantTier string
	}{
		{
			name:  "1 RCE on data-sensitive multi",
			in:    Input{CVSSVector: vecCIAHigh, Labels: map[string]string{"vdr.fedramp.io/security-impact-profile": "data-sensitive", "vdr.fedramp.io/multi-agency": "true"}},
			wantS: 1.00, wantWord: "Debilitating", wantTier: "N5",
		},
		{
			name:  "2 same RCE on dev-test single",
			in:    Input{CVSSVector: vecCIAHigh, Labels: map[string]string{"vdr.fedramp.io/security-impact-profile": "dev-test", "vdr.fedramp.io/multi-agency": "false"}},
			wantS: 0.63, wantWord: "Disruptive", wantTier: "N3",
		},
		{
			name:  "3 info-leak on data-sensitive multi",
			in:    Input{CVSSVector: vecInfoLow, Labels: map[string]string{"vdr.fedramp.io/security-impact-profile": "data-sensitive", "vdr.fedramp.io/multi-agency": "true"}},
			wantS: 0.33, wantWord: "Narrow", wantTier: "N2",
		},
		{
			name:  "4 RCE on cicd-pipeline tagged multi-agency",
			in:    Input{CVSSVector: vecCIAHigh, Labels: map[string]string{"vdr.fedramp.io/security-impact-profile": "cicd-pipeline", "vdr.fedramp.io/multi-agency": "true"}},
			wantS: 1.00, wantWord: "Debilitating", wantTier: "N5",
		},
		{
			name:  "5 DoS on public-edge single",
			in:    Input{CVSSVector: vecDoSHigh, Labels: map[string]string{"vdr.fedramp.io/security-impact-profile": "public-edge", "vdr.fedramp.io/multi-agency": "false"}},
			wantS: 0.84, wantWord: "Disruptive", wantTier: "N3",
		},
		{
			// A single High/High alignment is intentionally Disruptive under the
			// calibrated 0.933 Debilitating boundary.
			name:  "6 confidentiality on untagged (built-in default)",
			in:    Input{CVSSVector: vecConfHi},
			wantS: 0.84, wantWord: "Disruptive", wantTier: "N3",
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
	// Untagged resources resolve to the built-in H/H/H "unclassified" securityImpactProfile:
	// noisy (single-agency H/H/H + C:H/I:H/A:H => N4) but not the forced-multi N5.
	got := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "weird", WorkloadName: "mystery"})
	if got.SecurityImpactProfileSource != "default" || got.SecurityImpactProfile != "unclassified" {
		t.Errorf("source=%s archetype=%s, want default/unclassified", got.SecurityImpactProfileSource, got.SecurityImpactProfile)
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
	cfg.Defaults.SecurityImpactProfile = "" // clear the default => true fail-safe takes over
	got := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "weird", WorkloadName: "mystery"})
	if got.Tier != "N5" {
		t.Errorf("untagged Tier = %s, want N5 (fail-safe must force multi-agency)", got.Tier)
	}
	if got.SecurityImpactProfileSource != "failsafe" {
		t.Errorf("SecurityImpactProfileSource = %s, want failsafe", got.SecurityImpactProfileSource)
	}
}

func TestSingleAgencyControlPlaneCapsAtN4(t *testing.T) {
	cfg := Default()
	// A critical control-plane archetype tagged single-agency caps at N4 (Debilitating,
	// one agency); only an explicit multi-agency tag reaches N5.
	got := cfg.Score(Input{CVSSVector: vecCIAHigh, Labels: map[string]string{
		"vdr.fedramp.io/security-impact-profile": "cicd-pipeline",
		"vdr.fedramp.io/multi-agency":            "false",
	}})
	if got.Tier != "N4" {
		t.Errorf("Tier = %s, want N4 (single-agency must not reach N5)", got.Tier)
	}
}

func TestResolutionOrder(t *testing.T) {
	cfg := Default()
	cfg.NameRules = []NameRule{{Namespace: "kube-system", Match: "calico*", SecurityImpactProfile: "orchestrator"}}
	cfg.NamespaceRules = []NamespaceRule{{Match: "kube-system", SecurityImpactProfile: "internal-tooling"}}

	// Label wins over everything.
	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "calico-node",
		Labels: map[string]string{"vdr.fedramp.io/security-impact-profile": "app-tier"}})
	if r.SecurityImpactProfileSource != "label" || r.SecurityImpactProfile != "app-tier" {
		t.Errorf("label precedence failed: source=%s archetype=%s", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
	}

	// Name rule wins over namespace rule.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "calico-node"})
	if r.SecurityImpactProfileSource != "nameRule" || r.SecurityImpactProfile != "orchestrator" {
		t.Errorf("nameRule precedence failed: source=%s archetype=%s", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
	}

	// Namespace rule when no name rule matches.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "metrics-server"})
	if r.SecurityImpactProfileSource != "namespaceRule" || r.SecurityImpactProfile != "internal-tooling" {
		t.Errorf("namespaceRule fallback failed: source=%s archetype=%s", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
	}

	// Nothing matches => built-in cluster-default archetype.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "other", WorkloadName: "thing"})
	if r.SecurityImpactProfileSource != "default" || r.SecurityImpactProfile != "unclassified" {
		t.Errorf("expected default/unclassified, got source=%s archetype=%s", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
	}
}

func TestSIPOnlyTransport(t *testing.T) {
	cfg := Default()
	r := cfg.Score(Input{
		CVSSVector: vecCIAHigh,
		Labels: map[string]string{
			"vdr.fedramp.io/security-impact-profile": "cr-l_ir-l_ar-l",
			"vdr.fedramp.io/asset-archetype":         "generic-high",
			"vdr.fedramp.io/asset-value":             "High",
		},
	})
	if r.SecurityImpactProfile != "cr-l_ir-l_ar-l" || r.SecurityImpactProfileSource != "label" || r.CR != "L" || r.IR != "L" || r.AR != "L" {
		t.Fatalf("SIP label should be the only transport: %+v", r)
	}
}

// TestManagedNamespaceNoFalseN5 confirms that a managed-namespace workload
// classified by a namespace rule is scored on its merits (not floored to N5).
func TestManagedNamespaceNoFalseN5(t *testing.T) {
	cfg := Default()
	cfg.NamespaceRules = []NamespaceRule{{Match: "kube-system", SecurityImpactProfile: "internal-tooling"}}
	got := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "metrics-server-v1"})
	if got.Tier == "N5" {
		t.Errorf("managed-ns workload floored to N5; expected lower (got source=%s)", got.SecurityImpactProfileSource)
	}
	if got.SecurityImpactProfileSource != "namespaceRule" {
		t.Errorf("SecurityImpactProfileSource = %s, want namespaceRule", got.SecurityImpactProfileSource)
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
    securityImpactProfile: internal-tooling
nameRules:
  - namespace: kube-system
    match: "gke-metadata-server"
    securityImpactProfile: privileged-identity
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
	if cfg.LabelKeys.SecurityImpactProfile != "vdr.fedramp.io/security-impact-profile" {
		t.Errorf("LabelKeys.SecurityImpactProfile = %s, want default", cfg.LabelKeys.SecurityImpactProfile)
	}
	// File rules are applied.
	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "gke-metadata-server"})
	if r.SecurityImpactProfile != "privileged-identity" {
		t.Errorf("Archetype = %s, want privileged-identity from nameRule", r.SecurityImpactProfile)
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
	base := Input{CVSSVector: weakRCE, Labels: map[string]string{"vdr.fedramp.io/security-impact-profile": "data-sensitive"}}

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
	cfg.Defaults.SecurityImpactProfile = "cluster-default"

	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "new-ns", WorkloadName: "thing"})
	if r.SecurityImpactProfileSource != "default" || r.SecurityImpactProfile != "cluster-default" {
		t.Fatalf("source=%s archetype=%s, want default/cluster-default", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
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
  securityImpactProfile: cluster-default
nameRules:
  - {namespace: rally, match: postgres, securityImpactProfile: data-backbone}
namespaceRules:
  - {match: kube-system, securityImpactProfile: internal-tooling}
`,
	}
	if err := cfg.ApplyClusterDefaults(data); err != nil {
		t.Fatalf("ApplyClusterDefaults: %v", err)
	}
	if cfg.Defaults.Class != "C" {
		t.Errorf("Class = %s, want C (scalar override)", cfg.Defaults.Class)
	}
	if cfg.Defaults.SecurityImpactProfile != "cluster-default" {
		t.Errorf("default archetype = %s, want cluster-default (from embedded doc)", cfg.Defaults.SecurityImpactProfile)
	}
	if r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "postgres"}); r.SecurityImpactProfile != "data-backbone" || r.SecurityImpactProfileSource != "nameRule" {
		t.Errorf("embedded nameRule not applied: %s/%s", r.SecurityImpactProfile, r.SecurityImpactProfileSource)
	}
	if _, ok := cfg.Archetypes["data-sensitive"]; !ok {
		t.Error("built-in archetype catalog should survive ConfigMap merge")
	}

	// An embedded doc referencing an unknown archetype is rejected.
	bad := Default()
	if err := bad.ApplyClusterDefaults(map[string]string{"scoring": "namespaceRules:\n  - {match: x, securityImpactProfile: nope}\n"}); err == nil {
		t.Error("expected validate error for unknown archetype in ConfigMap doc")
	}
}

func TestRetiredConfigTransportsAreRejected(t *testing.T) {
	cfg := Default()
	for name, data := range map[string]map[string]string{
		"scalar assetValue": {"assetValue": "Medium"},
		"rule assetValue":   {"scoring.yaml": "nameRules:\n  - {match: api, assetValue: Low}\n"},
		"rule archetype":    {"scoring.yaml": "nameRules:\n  - {match: api, archetype: generic-low}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cfg.ApplyClusterDefaults(data); err == nil {
				t.Fatal("retired transport was accepted")
			}
		})
	}
}

func TestPlatformFoundationArchetype(t *testing.T) {
	cfg := Default()
	a, ok := cfg.Archetypes["platform-foundation"]
	if !ok {
		t.Fatal("platform-foundation archetype missing from built-in catalog")
	}
	if a.CR != "L" || a.IR != "H" || a.AR != "H" {
		t.Errorf("platform-foundation = %+v, want CR:L IR:H AR:H", a)
	}
	lbl := map[string]string{"vdr.fedramp.io/security-impact-profile": "platform-foundation"}
	// One A:H/AR:H alignment is Disruptive under the compound-impact boundary.
	if got := cfg.Score(Input{CVSSVector: vecDoSHigh, Labels: lbl}).Tier; got != "N3" {
		t.Errorf("A:H DoS Tier = %s, want N3", got)
	}
	// Confidentiality-only High (C:H) => N2 (metadata recon only, CR:L).
	if got := cfg.Score(Input{CVSSVector: vecConfHi, Labels: lbl}).Tier; got != "N2" {
		t.Errorf("C:H Tier = %s, want N2 (CR:L)", got)
	}
}

func TestCloudAndGenericArchetypes(t *testing.T) {
	cfg := Default()
	want := map[string]Archetype{
		"cicd-pipeline":       {Lens: "control", CR: "H", IR: "H", AR: "M"},
		"orchestrator":        {Lens: "control", CR: "M", IR: "M", AR: "H"},
		"config-actuation":    {Lens: "control", CR: "M", IR: "H", AR: "M"},
		"identity-secrets":    {Lens: "control", CR: "H", IR: "M", AR: "M"},
		"privileged-identity": {Lens: "control", CR: "H", IR: "H", AR: "M"},
		"scoped-identity":     {Lens: "control", CR: "M", IR: "H", AR: "M"},
		"security-tooling":    {Lens: "control", CR: "M", IR: "H", AR: "M"},
		"data-sensitive":      {Lens: "data", CR: "H", IR: "H", AR: "M"},
		"data-backbone":       {Lens: "data", CR: "H", IR: "H", AR: "M"},
		"public-data":         {Lens: "data", CR: "L", IR: "M", AR: "M"},
		"telemetry-data":      {Lens: "data", CR: "M", IR: "M", AR: "M"},
		"generic-high":        {Lens: "generic", CR: "H", IR: "H", AR: "H"},
		"generic-medium":      {Lens: "generic", CR: "M", IR: "M", AR: "M"},
		"generic-low":         {Lens: "generic", CR: "L", IR: "L", AR: "L"},
	}
	for name, expected := range want {
		actual, ok := cfg.Archetypes[name]
		if !ok {
			t.Errorf("archetype %q missing from built-in catalog", name)
			continue
		}
		if actual != expected {
			t.Errorf("archetype %q = %+v, want %+v", name, actual, expected)
		}
	}
}

func TestWordThresholds(t *testing.T) {
	cfg := Default()
	cases := []struct {
		s    float64
		want string
	}{
		{0.28, "Minimal"}, {defaultWordThresholds.Narrow, "Narrow"},
		{0.56, "Narrow"}, {defaultWordThresholds.Disruptive, "Disruptive"},
		{0.932, "Disruptive"}, {defaultWordThresholds.Debilitating, "Debilitating"},
		{1.0, "Debilitating"},
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

func TestCalibratedImpactAnchors(t *testing.T) {
	cfg := Default()
	cases := []struct {
		name      string
		vector    string
		archetype string
		wantS     float64
		wantWord  string
		wantTier  string
	}{
		{
			name:   "High impact at Low requirement starts Narrow",
			vector: vecConfHi, archetype: "dev-test",
			wantS: 0.28115159694107067, wantWord: "Narrow", wantTier: "N2",
		},
		{
			name:   "High impact at Medium requirement starts Disruptive",
			vector: vecConfHi, archetype: "app-tier",
			wantS: 0.5623031938821413, wantWord: "Disruptive", wantTier: "N3",
		},
		{
			name:   "one High High alignment remains Disruptive",
			vector: vecDoSHigh, archetype: "orchestrator",
			wantS: 0.843454790823212, wantWord: "Disruptive", wantTier: "N3",
		},
		{
			name:   "High High plus High Medium is Debilitating",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", archetype: "orchestrator",
			wantS: 0.9334233018443544, wantWord: "Debilitating", wantTier: "N4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cfg.Score(Input{CVSSVector: tc.vector, Labels: map[string]string{
				"vdr.fedramp.io/security-impact-profile": tc.archetype,
			}})
			if math.Abs(got.Severity-tc.wantS) > 1e-12 || got.Word != tc.wantWord || got.Tier != tc.wantTier {
				t.Fatalf("Score() = S %.15f, %s/%s; want %.15f, %s/%s", got.Severity, got.Word, got.Tier, tc.wantS, tc.wantWord, tc.wantTier)
			}
		})
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
	if loaded.WordThresholds.Narrow != defaultWordThresholds.Narrow || loaded.WordThresholds.Disruptive != defaultWordThresholds.Disruptive || loaded.WordThresholds.Debilitating != 0.90 {
		t.Errorf("merged thresholds = %+v, want narrow=%g disruptive=%g debilitating=0.90", loaded.WordThresholds, defaultWordThresholds.Narrow, defaultWordThresholds.Disruptive)
	}

	// Non-ascending thresholds are rejected.
	bad := Default()
	bad.WordThresholds = WordThresholds{Narrow: 0.6, Disruptive: 0.5, Debilitating: 0.85}
	if err := bad.validate(); err == nil {
		t.Error("expected error for non-ascending wordThresholds")
	}
}

func TestClusterConfigMapCannotSetThresholds(t *testing.T) {
	cfg := Default() // built-in standards-based thresholds
	// A ConfigMap embedded doc that tries to lower the Debilitating bar must be ignored.
	err := cfg.ApplyClusterDefaults(map[string]string{
		"class":        "C",
		"scoring.yaml": "wordThresholds:\n  debilitating: 0.50\nnameRules:\n  - {namespace: kube-system, match: \"calico*\", securityImpactProfile: orchestrator}\n",
	})
	if err != nil {
		t.Fatalf("ApplyClusterDefaults: %v", err)
	}
	if cfg.WordThresholds != defaultWordThresholds {
		t.Errorf("ConfigMap changed thresholds to %+v; want built-in %+v (ConfigMap must not set thresholds)", cfg.WordThresholds, defaultWordThresholds)
	}
	// The rest of the ConfigMap still applies.
	if cfg.Defaults.Class != "C" {
		t.Errorf("Class = %s, want C (other ConfigMap keys still apply)", cfg.Defaults.Class)
	}
	if got := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "kube-system", WorkloadName: "calico-node"}).SecurityImpactProfile; got != "orchestrator" {
		t.Errorf("nameRule from ConfigMap not applied: archetype=%s", got)
	}
}

func TestValidateRejectsUnknownDefaultArchetype(t *testing.T) {
	cfg := Default()
	cfg.Defaults.SecurityImpactProfile = "does-not-exist"
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
	if err := os.WriteFile(file, []byte("namespaceRules:\n  - match: foo\n    securityImpactProfile: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file); err == nil {
		t.Error("expected error for unknown archetype in rule")
	}
}

func TestKindRules(t *testing.T) {
	cfg := Default()
	cfg.NameRules = []NameRule{{Namespace: "rally", Match: "special-job", SecurityImpactProfile: "data-backbone"}}
	cfg.KindRules = []KindRule{{Kind: "Job", SecurityImpactProfile: "internal-tooling"}}
	cfg.NamespaceRules = []NamespaceRule{{Match: "rally", SecurityImpactProfile: "app-tier"}}

	// A standalone Job with no label or name rule gets the kind rule, which wins
	// over the namespace rule.
	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "postgres-admin-migrations", WorkloadKind: "Job"})
	if r.SecurityImpactProfileSource != "kindRule" || r.SecurityImpactProfile != "internal-tooling" {
		t.Errorf("kindRule match failed: source=%s archetype=%s", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
	}

	// A name rule still wins over the kind rule.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "special-job", WorkloadKind: "Job"})
	if r.SecurityImpactProfileSource != "nameRule" || r.SecurityImpactProfile != "data-backbone" {
		t.Errorf("nameRule precedence over kindRule failed: source=%s archetype=%s", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
	}

	// Other kinds fall through to the namespace rule.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "web", WorkloadKind: "Deployment"})
	if r.SecurityImpactProfileSource != "namespaceRule" || r.SecurityImpactProfile != "app-tier" {
		t.Errorf("non-matching kind fallthrough failed: source=%s archetype=%s", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
	}

	// An empty kind never matches a kind rule.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "other", WorkloadName: "thing"})
	if r.SecurityImpactProfileSource != "default" || r.SecurityImpactProfile != "unclassified" {
		t.Errorf("empty kind should skip kind rules: source=%s archetype=%s", r.SecurityImpactProfileSource, r.SecurityImpactProfile)
	}
}

func TestKindRuleScoping(t *testing.T) {
	cfg := Default()
	cfg.KindRules = []KindRule{{Kind: "Job", Namespace: "rally", Match: "*-generate-secrets", SecurityImpactProfile: "cr-l_ir-l_ar-l"}}

	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "kafka-generate-secrets", WorkloadKind: "Job"})
	if r.SecurityImpactProfileSource != "kindRule" || r.CR != "L" || r.IR != "L" || r.AR != "L" {
		t.Errorf("scoped SIP kindRule failed: source=%s CR/IR/AR=%s/%s/%s", r.SecurityImpactProfileSource, r.CR, r.IR, r.AR)
	}

	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "other", WorkloadName: "kafka-generate-secrets", WorkloadKind: "Job"})
	if r.SecurityImpactProfileSource == "kindRule" {
		t.Errorf("kindRule namespace scope not honored: source=%s", r.SecurityImpactProfileSource)
	}
}

func TestKindRuleValidation(t *testing.T) {
	cfg := Default()
	cfg.KindRules = []KindRule{{SecurityImpactProfile: "internal-tooling"}}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for kindRule without kind")
	}
	cfg.KindRules = []KindRule{{Kind: "Job"}}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for kindRule without securityImpactProfile")
	}
	cfg.KindRules = []KindRule{{Kind: "Job", SecurityImpactProfile: "not-a-real-archetype"}}
	if err := cfg.validate(); err == nil {
		t.Error("expected error for kindRule with unknown archetype")
	}
}

func TestClassAndMultiAgencySources(t *testing.T) {
	cfg := Default()

	// Nothing configured beyond the built-in rubric: both attribute to builtin.
	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "web", WorkloadKind: "Deployment"})
	if r.Class != "B" || r.ClassSource != "builtin" {
		t.Errorf("Class/ClassSource = %s/%s, want B/builtin", r.Class, r.ClassSource)
	}
	if r.MultiAgency || r.MultiAgencySource != "builtin" {
		t.Errorf("MultiAgency/Source = %v/%s, want false/builtin", r.MultiAgency, r.MultiAgencySource)
	}

	// With no default configured at all, the hard-coded Class B is attributed
	// to builtin.
	cfg.Defaults.Class = ""
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "web"})
	if r.Class != "B" || r.ClassSource != "builtin" {
		t.Errorf("Class/ClassSource = %s/%s, want B/builtin", r.Class, r.ClassSource)
	}

	// Cluster ConfigMap defaults are attributed to configMap, even when the
	// multiAgency value matches the built-in zero value.
	if err := cfg.ApplyClusterDefaults(map[string]string{"class": "C", "multiAgency": "false"}); err != nil {
		t.Fatalf("ApplyClusterDefaults error: %v", err)
	}
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "web"})
	if r.Class != "C" || r.ClassSource != "configMap" {
		t.Errorf("Class/ClassSource = %s/%s, want C/configMap", r.Class, r.ClassSource)
	}
	if r.MultiAgency || r.MultiAgencySource != "configMap" {
		t.Errorf("MultiAgency/Source = %v/%s, want false/configMap", r.MultiAgency, r.MultiAgencySource)
	}

	// Workload labels win and are attributed.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "web",
		Labels: map[string]string{"vdr.fedramp.io/class": "A", "vdr.fedramp.io/multi-agency": "true"}})
	if r.Class != "A" || r.ClassSource != "label" {
		t.Errorf("Class/ClassSource = %s/%s, want A/label", r.Class, r.ClassSource)
	}
	if !r.MultiAgency || r.MultiAgencySource != "label" {
		t.Errorf("MultiAgency/Source = %v/%s, want true/label", r.MultiAgency, r.MultiAgencySource)
	}

	// Namespace labels are attributed separately.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "web",
		NamespaceLabels: map[string]string{"vdr.fedramp.io/class": "D", "vdr.fedramp.io/multi-agency": "true"}})
	if r.Class != "D" || r.ClassSource != "namespaceLabel" {
		t.Errorf("Class/ClassSource = %s/%s, want D/namespaceLabel", r.Class, r.ClassSource)
	}
	if !r.MultiAgency || r.MultiAgencySource != "namespaceLabel" {
		t.Errorf("MultiAgency/Source = %v/%s, want true/namespaceLabel", r.MultiAgency, r.MultiAgencySource)
	}

	// Namespace glob list.
	cfg.MultiAgencyNamespaces = []string{"shared-*"}
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "shared-api", WorkloadName: "gw"})
	if !r.MultiAgency || r.MultiAgencySource != "multiAgencyNamespaces" {
		t.Errorf("MultiAgency/Source = %v/%s, want true/multiAgencyNamespaces", r.MultiAgency, r.MultiAgencySource)
	}
}

func TestFailsafeForcesMultiAgencySource(t *testing.T) {
	cfg := Default()
	cfg.Defaults.SecurityImpactProfile = "" // no default archetype => fail-safe path

	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "x", WorkloadName: "y"})
	if r.SecurityImpactProfileSource != "failsafe" {
		t.Fatalf("SecurityImpactProfileSource = %s, want failsafe", r.SecurityImpactProfileSource)
	}
	if !r.MultiAgency || r.MultiAgencySource != "failsafe" {
		t.Errorf("MultiAgency/Source = %v/%s, want true/failsafe (forced by fail-safe)", r.MultiAgency, r.MultiAgencySource)
	}

	// An explicit label saying true keeps its own attribution even on the
	// fail-safe path.
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "x", WorkloadName: "y",
		Labels: map[string]string{"vdr.fedramp.io/multi-agency": "true"}})
	if !r.MultiAgency || r.MultiAgencySource != "label" {
		t.Errorf("MultiAgency/Source = %v/%s, want true/label", r.MultiAgency, r.MultiAgencySource)
	}
}

func TestScoringConfigDefaultsAreAttributed(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "scoring.yaml")
	body := "defaults:\n  class: A\n  multiAgency: true\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(file)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	r := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "web"})
	if r.Class != "A" || r.ClassSource != "scoringConfig" {
		t.Errorf("Class/ClassSource = %s/%s, want A/scoringConfig", r.Class, r.ClassSource)
	}
	if !r.MultiAgency || r.MultiAgencySource != "scoringConfig" {
		t.Errorf("MultiAgency/Source = %v/%s, want true/scoringConfig", r.MultiAgency, r.MultiAgencySource)
	}

	// A ConfigMap layered on top takes over the attribution.
	if err := cfg.ApplyClusterDefaults(map[string]string{"class": "C"}); err != nil {
		t.Fatalf("ApplyClusterDefaults error: %v", err)
	}
	r = cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "rally", WorkloadName: "web"})
	if r.Class != "C" || r.ClassSource != "configMap" {
		t.Errorf("Class/ClassSource = %s/%s, want C/configMap", r.Class, r.ClassSource)
	}
}

func TestScoreCloudFunctionStaticallySetsN2NLEV(t *testing.T) {
	cfg := Default()

	// High impact, network vector finding on an asset that would normally be N4/N5
	highInput := Input{
		CVSSVector:        vecCIAHigh,
		Severity:          "CRITICAL",
		InternetReachable: true,
		EPSS:              0.95,
		Exploitation:      "active",
		Namespace:         "prod",
		WorkloadName:      "test-fn",
	}

	testCases := []struct {
		name         string
		workloadKind string
		labels       map[string]string
		wantN2NLEV   bool
	}{
		{
			name:         "WorkloadKind Function",
			workloadKind: "Function",
			wantN2NLEV:   true,
		},
		{
			name:         "WorkloadKind function (case-insensitive)",
			workloadKind: "function",
			wantN2NLEV:   true,
		},
		{
			name:         "Service with goog-managed-by cloudfunctions",
			workloadKind: "Service",
			labels:       map[string]string{"goog-managed-by": "cloudfunctions"},
			wantN2NLEV:   true,
		},
		{
			name:         "Service with goog-cloudfunctions-runtime",
			workloadKind: "Service",
			labels:       map[string]string{"goog-cloudfunctions-runtime": "python311"},
			wantN2NLEV:   true,
		},
		{
			name:         "Standard Service without function labels",
			workloadKind: "Service",
			wantN2NLEV:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			in := highInput
			in.WorkloadKind = tc.workloadKind
			in.Labels = tc.labels

			res := cfg.Score(in)
			if tc.wantN2NLEV {
				if res.Tier != "N2" {
					t.Errorf("Tier = %q, want N2", res.Tier)
				}
				if res.Word != "Narrow" {
					t.Errorf("Word = %q, want Narrow", res.Word)
				}
				if res.Column != "NLEV" {
					t.Errorf("Column = %q, want NLEV", res.Column)
				}
				if res.LEV {
					t.Errorf("LEV = true, want false")
				}
				if res.IRV {
					t.Errorf("IRV = true, want false")
				}
				if res.RemediationLabel != "192 days" {
					t.Errorf("RemediationLabel = %q, want 192 days", res.RemediationLabel)
				}
			} else {
				if res.Tier == "N2" && res.Column == "NLEV" {
					t.Errorf("Standard service unexpectedly scored as N2 NLEV")
				}
			}
		})
	}
}
