package scoring

import "testing"

func TestParseSecurityRequirementsCeiling(t *testing.T) {
	for _, value := range []string{"cr-h_ir-m_ar-l", "CR:H/IR:M/AR:L"} {
		requirements, ok := ParseSecurityRequirements(value)
		if !ok {
			t.Fatalf("ParseSecurityRequirements(%q) rejected a valid vector", value)
		}
		if got := requirements.String(); got != "CR:H/IR:M/AR:L" {
			t.Fatalf("normalized requirements = %q, want CR:H/IR:M/AR:L", got)
		}
		if got := requirements.WireValue(); got != "cr-h_ir-m_ar-l" {
			t.Fatalf("wire value = %q, want cr-h_ir-m_ar-l", got)
		}
	}

	for _, invalid := range []string{
		"",
		"cr-h_ir-m",
		"cr-high_ir-m_ar-l",
		"cr-x_ir-m_ar-l",
		"H/M/L",
	} {
		if _, ok := ParseSecurityRequirements(invalid); ok {
			t.Errorf("ParseSecurityRequirements(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestCapRequirements(t *testing.T) {
	got, recalculated := capRequirements(
		SecurityRequirements{CR: "H", IR: "M", AR: "H"},
		SecurityRequirements{CR: "M", IR: "H", AR: "L"},
	)
	if got.String() != "CR:M/IR:M/AR:L" {
		t.Fatalf("capped requirements = %s, want CR:M/IR:M/AR:L", got)
	}
	if !recalculated {
		t.Fatal("recalculated = false, want true")
	}

	got, recalculated = capRequirements(
		SecurityRequirements{CR: "L", IR: "M", AR: "H"},
		SecurityRequirements{CR: "H", IR: "H", AR: "H"},
	)
	if got.String() != "CR:L/IR:M/AR:H" || recalculated {
		t.Fatalf("nonbinding ceiling result = %s recalculated=%t", got, recalculated)
	}
}

func TestOptionalCeilingRecalculatesArchetypeScore(t *testing.T) {
	cfg := Default()
	input := Input{
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Labels: map[string]string{
			"vdr.fedramp.io/asset-archetype": "data-sensitive",
		},
	}

	uncapped := cfg.Score(input)
	if uncapped.Archetype != "data-sensitive" ||
		uncapped.CR != "H" ||
		uncapped.IR != "H" ||
		uncapped.AR != "M" {
		t.Fatalf("uncapped archetype result = %+v", uncapped)
	}
	if uncapped.SecurityRequirementsCeiling != "" ||
		uncapped.SecurityRequirementsCeilingSource != "" ||
		uncapped.ArchetypeRequirements != "" ||
		uncapped.Recalculated {
		t.Fatalf("absent ceiling must be silent: %+v", uncapped)
	}

	if err := cfg.ApplyClusterDefaults(map[string]string{
		"securityRequirementsCeiling": "cr-m_ir-l_ar-h",
	}); err != nil {
		t.Fatalf("ApplyClusterDefaults: %v", err)
	}
	capped := cfg.Score(input)
	if capped.Archetype != "data-sensitive" ||
		capped.ArchetypeSource != "label" ||
		capped.ArchetypeRequirements != "CR:H/IR:H/AR:M" ||
		capped.SecurityRequirementsCeiling != "CR:M/IR:L/AR:H" ||
		capped.SecurityRequirementsCeilingSource != "configMap" ||
		!capped.Recalculated ||
		capped.CR != "M" ||
		capped.IR != "L" ||
		capped.AR != "M" {
		t.Fatalf("ConfigMap-capped archetype result = %+v", capped)
	}

	if err := cfg.SetRuntimeSecurityRequirementsCeiling("CR:H/IR:M/AR:L"); err != nil {
		t.Fatalf("SetRuntimeSecurityRequirementsCeiling: %v", err)
	}
	runtime := cfg.Score(input)
	if runtime.SecurityRequirementsCeiling != "CR:H/IR:M/AR:L" ||
		runtime.SecurityRequirementsCeilingSource != "runtime" ||
		!runtime.Recalculated ||
		runtime.CR != "H" ||
		runtime.IR != "M" ||
		runtime.AR != "L" {
		t.Fatalf("runtime-capped archetype result = %+v", runtime)
	}
}

func TestInvalidDeclaredCeilingIsRejected(t *testing.T) {
	cfg := Default()
	if err := cfg.ApplyClusterDefaults(map[string]string{
		"securityRequirementsCeiling": "high/moderate/low",
	}); err == nil {
		t.Fatal("ApplyClusterDefaults accepted an invalid ceiling")
	}
	if err := cfg.SetRuntimeSecurityRequirementsCeiling("not-a-vector"); err == nil {
		t.Fatal("SetRuntimeSecurityRequirementsCeiling accepted an invalid ceiling")
	}
}

func TestEmbeddedConfigMapCeilingIsNormalizedAndAttributed(t *testing.T) {
	cfg := Default()
	cfg.SecurityRequirementsCeiling = "cr-m_ir-l_ar-h"
	cfg.ceilingOrigin = "scoringConfig"
	if err := cfg.ApplyClusterDefaults(map[string]string{
		"scoring.yaml": "securityRequirementsCeiling: CR:M/IR:L/AR:H\n",
	}); err != nil {
		t.Fatalf("ApplyClusterDefaults: %v", err)
	}
	if cfg.SecurityRequirementsCeiling != "cr-m_ir-l_ar-h" {
		t.Fatalf("normalized ceiling = %q", cfg.SecurityRequirementsCeiling)
	}
	result := cfg.Score(Input{})
	if result.SecurityRequirementsCeilingSource != "configMap" {
		t.Fatalf(
			"SecurityRequirementsCeilingSource = %q, want configMap",
			result.SecurityRequirementsCeilingSource,
		)
	}
}
