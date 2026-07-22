package scoring

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuiltinReasonCodeRegistry(t *testing.T) {
	cfg := Default()
	wantDisclosure := map[string]string{
		"public-content": "L", "opaque-transit": "L", "routing-metadata": "L", "synthetic-data": "L",
		"service-content": "M", "ops-metadata": "M", "security-evidence": "M", "control-metadata": "M", "scoped-access": "M",
		"federal-records": "H", "regulated-data": "H", "restricted-evidence": "H", "root-secrets": "H", "privileged-access": "H",
	}
	wantTrustedChange := map[string]string{
		"advisory-output": "L", "opaque-forwarding": "L", "disposable-state": "L", "isolated-testing": "L",
		"bounded-processing": "M", "scoped-write": "M", "record-keeping": "M", "coordination-state": "M",
		"authoritative-record": "H", "config-control": "H", "identity-control": "H", "security-enforcement": "H",
		"release-control": "H", "foundation-control": "H", "trust-anchor": "H",
	}
	wantDependency := map[string]string{
		"deferrable-work": "L", "optional-tooling": "L", "nonproduction": "L",
		"bounded-service": "M", "operations-support": "M", "shared-degradation": "M", "change-deferred": "M",
		"shared-critical-path": "H", "mission-essential": "H", "protection-critical": "H", "recovery-critical": "H",
	}
	if !reflect.DeepEqual(cfg.reasonCodes.Disclosure, wantDisclosure) {
		t.Errorf("disclosure reasons = %#v, want %#v", cfg.reasonCodes.Disclosure, wantDisclosure)
	}
	if !reflect.DeepEqual(cfg.reasonCodes.TrustedChange, wantTrustedChange) {
		t.Errorf("trusted-change reasons = %#v, want %#v", cfg.reasonCodes.TrustedChange, wantTrustedChange)
	}
	if !reflect.DeepEqual(cfg.reasonCodes.Dependency, wantDependency) {
		t.Errorf("dependency reasons = %#v, want %#v", cfg.reasonCodes.Dependency, wantDependency)
	}
}

func TestCompositeArchetypesCoverAllRequirementVectors(t *testing.T) {
	cfg := Default()
	disclosure := []struct{ token, level string }{
		{token: "public-content", level: "L"},
		{token: "service-content", level: "M"},
		{token: "regulated-data", level: "H"},
	}
	trustedChange := []struct{ token, level string }{
		{token: "advisory-output", level: "L"},
		{token: "bounded-processing", level: "M"},
		{token: "authoritative-record", level: "H"},
	}
	dependency := []struct{ token, level string }{
		{token: "deferrable-work", level: "L"},
		{token: "bounded-service", level: "M"},
		{token: "shared-critical-path", level: "H"},
	}

	seen := map[string]bool{}
	for _, cr := range disclosure {
		for _, ir := range trustedChange {
			for _, ar := range dependency {
				trace := fmt.Sprintf("%s.%s.%s", cr.token, ir.token, ar.token)
				if _, explicitlyConfigured := cfg.Archetypes[trace]; explicitlyConfigured {
					t.Fatalf("trace %q should resolve natively, not from an explicit catalog entry", trace)
				}
				got, ok := cfg.lookupArchetype(trace)
				if !ok {
					t.Fatalf("lookupArchetype(%q) was not recognized", trace)
				}
				if got.Lens != compositeLens || got.CR != cr.level || got.IR != ir.level || got.AR != ar.level {
					t.Errorf("lookupArchetype(%q) = %+v, want composite %s/%s/%s", trace, got, cr.level, ir.level, ar.level)
				}
				seen[got.CR+got.IR+got.AR] = true
			}
		}
	}
	if len(seen) != 27 {
		t.Fatalf("represented vectors = %d, want 27", len(seen))
	}
}

func TestCompositeTraceScoresFromLabelAndRuleWithoutCatalogEntry(t *testing.T) {
	const trace = "regulated-data.authoritative-record.shared-critical-path"
	cfg := Default()

	fromLabel := cfg.Score(Input{
		CVSSVector: vecCIAHigh,
		Labels: map[string]string{
			"vdr.fedramp.io/asset-archetype": trace,
		},
	})
	if fromLabel.Archetype != trace || fromLabel.ArchetypeSource != "label" ||
		fromLabel.CR != "H" || fromLabel.IR != "H" || fromLabel.AR != "H" {
		t.Fatalf("composite label result = %+v", fromLabel)
	}

	cfg.NameRules = []NameRule{{
		Namespace: "records",
		Match:     "database-*",
		Archetype: trace,
	}}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate composite rule: %v", err)
	}
	fromRule := cfg.Score(Input{
		CVSSVector:   vecCIAHigh,
		Namespace:    "records",
		WorkloadName: "database-primary",
	})
	if fromRule.Archetype != trace || fromRule.ArchetypeSource != "nameRule" ||
		fromRule.CR != "H" || fromRule.IR != "H" || fromRule.AR != "H" {
		t.Fatalf("composite rule result = %+v", fromRule)
	}
}

func TestClusterConfigAcceptsCompositeRulesWithoutArchetypeEntries(t *testing.T) {
	cfg := Default()
	err := cfg.ApplyClusterDefaults(map[string]string{
		"scoring.yaml": "nameRules:\n  - {namespace: ops, match: logs-*, archetype: regulated-data.record-keeping.operations-support}\n",
	})
	if err != nil {
		t.Fatalf("ApplyClusterDefaults: %v", err)
	}
	got := cfg.Score(Input{CVSSVector: vecCIAHigh, Namespace: "ops", WorkloadName: "logs-node"})
	if got.ArchetypeSource != "nameRule" || got.CR != "H" || got.IR != "M" || got.AR != "M" {
		t.Fatalf("composite ConfigMap rule result = %+v", got)
	}
}

func TestInvalidCompositeTraceFailsLoud(t *testing.T) {
	const invalid = "regulated-data.no-such-change.shared-critical-path"
	cfg := Default()
	got := cfg.Score(Input{
		CVSSVector: vecCIAHigh,
		Labels: map[string]string{
			"vdr.fedramp.io/asset-archetype": invalid,
		},
	})
	if got.Archetype != "unclassified" || got.ArchetypeSource != "label-unknown" ||
		got.CR != "H" || got.IR != "H" || got.AR != "H" || !got.MultiAgency {
		t.Fatalf("invalid composite label did not fail safe: %+v", got)
	}

	cfg.NameRules = []NameRule{{Match: "*", Archetype: invalid}}
	if err := cfg.validate(); err == nil {
		t.Fatal("invalid composite rule was accepted")
	}
}

func TestExplicitCompositeEntryMustMatchGovernedVector(t *testing.T) {
	const trace = "public-content.bounded-processing.bounded-service"
	cfg := Default()
	cfg.Archetypes[trace] = Archetype{Lens: compositeLens, CR: "L", IR: "M", AR: "M"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("matching compatibility entry rejected: %v", err)
	}

	cfg.Archetypes[trace] = Archetype{Lens: compositeLens, CR: "H", IR: "H", AR: "H"}
	if err := cfg.validate(); err == nil {
		t.Fatal("conflicting composite compatibility entry was accepted")
	}
}

func TestReasonCodesCannotBeOverridden(t *testing.T) {
	const override = "reasonCodes:\n  disclosure:\n    public-content: H\n"
	cfg := Default()
	if err := cfg.ApplyClusterDefaults(map[string]string{"scoring.yaml": override}); err == nil || !strings.Contains(err.Error(), "cannot be overridden") {
		t.Fatalf("cluster reason-code override error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "scoring.yaml")
	if err := os.WriteFile(path, []byte(override), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "cannot be overridden") {
		t.Fatalf("file reason-code override error = %v", err)
	}
}
