package scoring

import "testing"

// dataSensitiveN5 builds an input that scores PAIN-5 (data-sensitive, multi-agency,
// C:H/I:H/A:H), varying the exploitability/reachability inputs.
func dataSensitiveN5(epss float64, exploitation string, irv bool) Input {
	return Input{
		CVSSVector:        vecCIAHigh,
		Labels:            map[string]string{"vdr.fedramp.io/asset-archetype": "data-sensitive", "vdr.fedramp.io/multi-agency": "true"},
		EPSS:              epss,
		Exploitation:      exploitation,
		InternetReachable: irv,
	}
}

func TestRemediationColumnsAndMatrix(t *testing.T) {
	cfg := Default()
	cfg.Defaults.Class = "C"

	cases := []struct {
		name      string
		in        Input
		wantCol   string
		wantDays  float64
		wantLabel string
		wantLEV   bool
	}{
		{"LEV+IRV via EPSS", dataSensitiveN5(0.8, "none", true), "LEV+IRV", 2, "2 days", true},
		{"NLEV (low EPSS, no active)", dataSensitiveN5(0.49, "none", true), "NLEV", 16, "16 days", false},
		{"LEV+NIRV via active exploitation", dataSensitiveN5(0.49, "active", false), "LEV+NIRV", 4, "4 days", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := cfg.Score(tc.in)
			if r.Tier != "N5" {
				t.Fatalf("Tier = %s, want N5 (precondition)", r.Tier)
			}
			if r.Column != tc.wantCol {
				t.Errorf("Column = %s, want %s", r.Column, tc.wantCol)
			}
			if r.DeadlineDays != tc.wantDays {
				t.Errorf("DeadlineDays = %v, want %v", r.DeadlineDays, tc.wantDays)
			}
			if r.RemediationLabel != tc.wantLabel {
				t.Errorf("RemediationLabel = %q, want %q", r.RemediationLabel, tc.wantLabel)
			}
			if r.LEV != tc.wantLEV {
				t.Errorf("LEV = %v, want %v", r.LEV, tc.wantLEV)
			}
		})
	}
}

func TestRemediationClassTables(t *testing.T) {
	// N5 + LEV+IRV deadline per class.
	wants := map[string]struct {
		days  float64
		label string
	}{
		"A": {4, "4 days"},
		"B": {4, "4 days"},
		"C": {2, "2 days"},
		"D": {0.5, "12 hours"},
	}
	for class, want := range wants {
		cfg := Default()
		cfg.Defaults.Class = class
		r := cfg.Score(dataSensitiveN5(0.9, "active", true))
		if r.Class != class {
			t.Errorf("class %s: resolved Class = %s", class, r.Class)
		}
		if r.DeadlineDays != want.days || r.RemediationLabel != want.label {
			t.Errorf("class %s: got %v/%q, want %v/%q", class, r.DeadlineDays, r.RemediationLabel, want.days, want.label)
		}
	}
}

func TestRemediationN1NoDeadline(t *testing.T) {
	cfg := Default()
	// dev-test (L/L/L) with a tiny confidentiality-only impact => Minimal => N1.
	r := cfg.Score(Input{
		CVSSVector: vecInfoLow,
		Labels:     map[string]string{"vdr.fedramp.io/asset-archetype": "dev-test", "vdr.fedramp.io/multi-agency": "false"},
		EPSS:       0.9, Exploitation: "active", InternetReachable: true,
	})
	if r.Tier != "N1" {
		t.Fatalf("Tier = %s, want N1 (precondition)", r.Tier)
	}
	if r.DeadlineDays >= 0 {
		t.Errorf("DeadlineDays = %v, want < 0 (no FedRAMP deadline for N1)", r.DeadlineDays)
	}
}

func TestLEVThresholdBoundary(t *testing.T) {
	cfg := Default() // threshold 0.50
	if !cfg.isLEV(Input{EPSS: 0.50}) {
		t.Error("EPSS 0.50 should be LEV (>= threshold)")
	}
	if cfg.isLEV(Input{EPSS: 0.49}) {
		t.Error("EPSS 0.49 should not be LEV")
	}
	if !cfg.isLEV(Input{EPSS: -1, Exploitation: "active"}) {
		t.Error("active exploitation should be LEV regardless of EPSS")
	}
	if cfg.isLEV(Input{EPSS: -1, Exploitation: "none"}) {
		t.Error("no EPSS and not active should not be LEV")
	}
}

func TestClassHierarchy(t *testing.T) {
	cfg := Default()
	cfg.Defaults.Class = "B"
	wl := map[string]string{"vdr.fedramp.io/class": "D"}
	ns := map[string]string{"vdr.fedramp.io/class": "C"}

	if got := cfg.Score(Input{CVSSVector: vecCIAHigh, Labels: wl, NamespaceLabels: ns}).Class; got != "D" {
		t.Errorf("workload label should win: Class = %s, want D", got)
	}
	if got := cfg.Score(Input{CVSSVector: vecCIAHigh, NamespaceLabels: ns}).Class; got != "C" {
		t.Errorf("namespace label should win over default: Class = %s, want C", got)
	}
	if got := cfg.Score(Input{CVSSVector: vecCIAHigh}).Class; got != "B" {
		t.Errorf("default should apply: Class = %s, want B", got)
	}
}

func TestApplyClusterDefaults(t *testing.T) {
	cfg := Default()
	cfg.ApplyClusterDefaults(map[string]string{"class": "C", "multiAgency": "true"})
	if cfg.Defaults.Class != "C" {
		t.Errorf("Defaults.Class = %s, want C", cfg.Defaults.Class)
	}
	if !cfg.Defaults.MultiAgency {
		t.Error("Defaults.MultiAgency should be true from ConfigMap")
	}
	// hyphenated key variant.
	cfg2 := Default()
	cfg2.ApplyClusterDefaults(map[string]string{"multi-agency": "true"})
	if !cfg2.Defaults.MultiAgency {
		t.Error("multi-agency (hyphen) key should be honored")
	}
}

func TestMultiAgencyHierarchy(t *testing.T) {
	cfg := Default()
	cfg.MultiAgencyNamespaces = []string{"tenant-*"}
	// data-sensitive (H/H/H) + C:H/I:H/A:H => Debilitating; multi => N5, single => N4.
	base := Input{CVSSVector: vecCIAHigh, Labels: map[string]string{"vdr.fedramp.io/asset-archetype": "data-sensitive"}}

	in := base
	in.Namespace = "tenant-x"
	if got := cfg.Score(in).Tier; got != "N5" {
		t.Errorf("multiAgencyNamespaces match should be multi: Tier = %s, want N5", got)
	}
	in = base
	in.Namespace = "other"
	if got := cfg.Score(in).Tier; got != "N4" {
		t.Errorf("non-matching namespace should be single: Tier = %s, want N4", got)
	}
	// namespace label overrides the namespace-glob rule.
	in = base
	in.Namespace = "tenant-x"
	in.NamespaceLabels = map[string]string{"vdr.fedramp.io/multi-agency": "false"}
	if got := cfg.Score(in).Tier; got != "N4" {
		t.Errorf("namespace label false should override glob: Tier = %s, want N4", got)
	}
}

func TestNamespaceLabelArchetype(t *testing.T) {
	cfg := Default()
	r := cfg.Score(Input{
		CVSSVector:      vecCIAHigh,
		Namespace:       "team-a",
		WorkloadName:    "svc",
		NamespaceLabels: map[string]string{"vdr.fedramp.io/asset-archetype": "dev-test"},
	})
	if r.Archetype != "dev-test" || r.ArchetypeSource != "namespaceLabel" {
		t.Errorf("archetype=%s source=%s, want dev-test/namespaceLabel", r.Archetype, r.ArchetypeSource)
	}
}
