package scoring

import "testing"

func TestParseSecurityRequirements(t *testing.T) {
	requirements, ok := ParseSecurityRequirements("cr-h_ir-m_ar-l")
	if !ok {
		t.Fatal("ParseSecurityRequirements rejected a valid vector")
	}
	if got := requirements.String(); got != "CR:H/IR:M/AR:L" {
		t.Fatalf("normalized requirements = %q, want CR:H/IR:M/AR:L", got)
	}
	if got := requirements.labelValue(); got != "cr-h_ir-m_ar-l" {
		t.Fatalf("wire value = %q, want cr-h_ir-m_ar-l", got)
	}

	for _, invalid := range []string{
		"",
		"cr-h_ir-m",
		"cr-high_ir-m_ar-l",
		"CR:H/IR:M/AR:L",
		"cr-x_ir-m_ar-l",
	} {
		if _, ok := ParseSecurityRequirements(invalid); ok {
			t.Errorf("ParseSecurityRequirements(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestNativeSecurityRequirementsSchema(t *testing.T) {
	cfg := Default()
	err := cfg.ApplyClusterDefaults(map[string]string{
		"class": "C",
		"scoring.yaml": `
labelKeys:
  securityRequirements: vdr.fedramp.io/security-requirements
nameRules:
  - {namespace: app, match: api, securityRequirements: cr-m_ir-h_ar-l}
`,
	})
	if err != nil {
		t.Fatalf("ApplyClusterDefaults: %v", err)
	}

	fromLabel := cfg.Score(Input{
		CVSSVector: vecCIAHigh,
		Labels: map[string]string{
			"vdr.fedramp.io/security-requirements": "cr-h_ir-l_ar-m",
		},
	})
	if fromLabel.SecurityRequirements != "CR:H/IR:L/AR:M" || fromLabel.SecurityRequirementsSource != "label" {
		t.Fatalf("label result = %+v", fromLabel)
	}

	fromRule := cfg.Score(Input{
		CVSSVector:   vecCIAHigh,
		Namespace:    "app",
		WorkloadName: "api",
	})
	if fromRule.SecurityRequirements != "CR:M/IR:H/AR:L" || fromRule.SecurityRequirementsSource != "nameRule" {
		t.Fatalf("rule result = %+v", fromRule)
	}
}

func TestTransitionalGeneratedSchemaDoesNotNeedArchetypeCatalogLookup(t *testing.T) {
	cfg := Default()
	err := cfg.ApplyClusterDefaults(map[string]string{
		"scoring.yaml": `
labelKeys:
  archetype: vdr.fedramp.io/security-requirements
nameRules:
  - {namespace: app, match: api, archetype: cr-h_ir-m_ar-l}
`,
	})
	if err != nil {
		t.Fatalf("ApplyClusterDefaults: %v", err)
	}

	got := cfg.Score(Input{
		CVSSVector:   vecCIAHigh,
		Namespace:    "app",
		WorkloadName: "api",
	})
	if got.SecurityRequirements != "CR:H/IR:M/AR:L" || got.SecurityRequirementsSource != "nameRule" {
		t.Fatalf("transitional rule result = %+v", got)
	}
}

func TestLegacyArchetypeModeTakesPrecedence(t *testing.T) {
	cfg := Default()
	// The new generated ConfigMap uses this transitional alias. Legacy mode must
	// still read the canonical old label key when explicitly requested.
	cfg.LabelKeys.Archetype = "vdr.fedramp.io/security-requirements"
	input := Input{
		CVSSVector: vecCIAHigh,
		Labels: map[string]string{
			"vdr.fedramp.io/security-requirements": "cr-l_ir-l_ar-l",
			"vdr.fedramp.io/asset-archetype":       "data-sensitive",
		},
	}

	raw := cfg.Score(input)
	if raw.SecurityRequirements != "CR:L/IR:L/AR:L" || raw.Archetype != "cr-l_ir-l_ar-l" {
		t.Fatalf("default raw-vector result = %+v", raw)
	}

	cfg.UseLegacyArchetypes(true)
	if !cfg.LegacyArchetypesEnabled() {
		t.Fatal("LegacyArchetypesEnabled = false after enabling it")
	}
	legacy := cfg.Score(input)
	if legacy.SecurityRequirements != "CR:H/IR:H/AR:M" ||
		legacy.Archetype != "data-sensitive" ||
		legacy.SecurityRequirementsSource != "label" {
		t.Fatalf("legacy result = %+v", legacy)
	}
}

func TestLegacyArchetypeModeUsesLegacyDefault(t *testing.T) {
	cfg := Default()
	cfg.UseLegacyArchetypes(true)

	got := cfg.Score(Input{CVSSVector: vecCIAHigh})
	if got.Archetype != "unclassified" ||
		got.SecurityRequirements != "CR:H/IR:H/AR:H" ||
		got.SecurityRequirementsSource != "default" {
		t.Fatalf("legacy default result = %+v", got)
	}
}
