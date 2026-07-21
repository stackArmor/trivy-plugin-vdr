package reachability

import (
	"reflect"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestEvaluateChainableEntrypoint(t *testing.T) {
	const (
		v3NetworkPartial = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
		v3NetworkFull    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		v3LocalPartial   = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
		v4NetworkFull    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	)

	tests := []struct {
		name              string
		vector            string
		cwes              []string
		wantStatus        string
		wantReasons       []string
		wantContext       string
		wantContextSource string
	}{
		{
			name:        "strict execution CWE is high confidence",
			vector:      v3NetworkPartial,
			cwes:        []string{"CWE-94"},
			wantStatus:  ChainableEntrypointHighConfidence,
			wantReasons: []string{"network-attack-vector", "strict-execution-cwe"},
		},
		{
			name:        "strict execution CWE still requires network attack vector",
			vector:      v3LocalPartial,
			cwes:        []string{"CWE-94"},
			wantStatus:  ChainableEntrypointNone,
			wantReasons: []string{"attack-vector-not-network"},
		},
		{
			name:        "full impact plus combined execution CWE is high confidence",
			vector:      v3NetworkFull,
			cwes:        []string{"CWE-97"},
			wantStatus:  ChainableEntrypointHighConfidence,
			wantReasons: []string{"network-attack-vector", "full-vulnerable-system-impact", "combined-execution-cwe"},
		},
		{
			name:        "full impact alone is possible",
			vector:      v3NetworkFull,
			wantStatus:  ChainableEntrypointPossible,
			wantReasons: []string{"full-impact-without-execution-signal"},
		},
		{
			name:        "loose execution CWE without full impact is possible",
			vector:      v3NetworkPartial,
			cwes:        []string{"CWE-494"},
			wantStatus:  ChainableEntrypointPossible,
			wantReasons: []string{"possible-execution-cwe"},
		},
		{
			name:              "context-dependent execution CWE remains possible",
			vector:            v3NetworkFull,
			cwes:              []string{"CWE-1336"},
			wantStatus:        ChainableEntrypointPossible,
			wantReasons:       []string{"network-attack-vector", "full-vulnerable-system-impact", "execution-context-required"},
			wantContext:       "unknown",
			wantContextSource: "not-collected",
		},
		{
			name:        "CVSS v4 vulnerable-system impact is supported",
			vector:      v4NetworkFull,
			cwes:        []string{"CWE-494"},
			wantStatus:  ChainableEntrypointHighConfidence,
			wantReasons: []string{"network-attack-vector", "full-vulnerable-system-impact", "combined-execution-cwe"},
		},
		{
			name:        "unrelated CWE has no chainable signal",
			vector:      v3NetworkPartial,
			cwes:        []string{"CWE-79"},
			wantStatus:  ChainableEntrypointNone,
			wantReasons: []string{"no-chainable-execution-signal"},
		},
		{
			name:        "missing attack vector is recorded",
			cwes:        []string{"CWE-94"},
			wantStatus:  ChainableEntrypointNone,
			wantReasons: []string{"attack-vector-unavailable"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateChainableEntrypoint(model.Finding{CVSSVector: tt.vector, CWEs: tt.cwes})
			if got.CandidateStatus != tt.wantStatus {
				t.Fatalf("CandidateStatus = %q, want %q: %#v", got.CandidateStatus, tt.wantStatus, got)
			}
			if !reflect.DeepEqual(got.ReasonCodes, tt.wantReasons) {
				t.Fatalf("ReasonCodes = %v, want %v", got.ReasonCodes, tt.wantReasons)
			}
			if got.ExecutionContext != tt.wantContext || got.ExecutionContextSource != tt.wantContextSource {
				t.Fatalf("execution context = %q/%q, want %q/%q", got.ExecutionContext, got.ExecutionContextSource, tt.wantContext, tt.wantContextSource)
			}
			if got.PolicyVersion != ChainableEntrypointPolicyVersion {
				t.Fatalf("PolicyVersion = %q, want %q", got.PolicyVersion, ChainableEntrypointPolicyVersion)
			}
			if got.Qualification != ChainableEntrypointNotQualifying || got.Qualifies || !got.ActiveFinding || got.InternetAccessible {
				t.Fatalf("unjoined qualification = %#v, want active candidate not yet qualified by exposure", got)
			}
		})
	}
}

func TestQualifyChainableEntrypointRequiresActiveFindingExposureAndHighConfidence(t *testing.T) {
	high := EvaluateChainableEntrypoint(model.Finding{
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
		CWEs:       []string{"CWE-94"},
	})
	possible := EvaluateChainableEntrypoint(model.Finding{
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	})
	suppressed := EvaluateChainableEntrypoint(model.Finding{
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
		CWEs:       []string{"CWE-94"},
		Suppressed: true,
	})

	tests := []struct {
		name               string
		value              *model.ChainableEntrypoint
		internetAccessible bool
		wantQualification  string
		wantQualifies      bool
	}{
		{name: "active exposed high-confidence candidate qualifies", value: high, internetAccessible: true, wantQualification: ChainableEntrypointQualifying, wantQualifies: true},
		{name: "unexposed high-confidence candidate does not qualify", value: high, wantQualification: ChainableEntrypointNotQualifying},
		{name: "active exposed possible candidate stays review", value: possible, internetAccessible: true, wantQualification: ChainableEntrypointReview},
		{name: "suppressed exposed high-confidence candidate does not qualify", value: suppressed, internetAccessible: true, wantQualification: ChainableEntrypointNotQualifying},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := QualifyChainableEntrypoint(tt.value, tt.internetAccessible)
			if got.Qualification != tt.wantQualification || got.Qualifies != tt.wantQualifies {
				t.Fatalf("qualification = %q/%t, want %q/%t: %#v", got.Qualification, got.Qualifies, tt.wantQualification, tt.wantQualifies, got)
			}
			if got.InternetAccessible != tt.internetAccessible {
				t.Fatalf("InternetAccessible = %t, want %t", got.InternetAccessible, tt.internetAccessible)
			}
		})
	}
}

func TestEvaluateChainableEntrypointPreservesNormalizedSourceFacts(t *testing.T) {
	finding := model.Finding{
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
		CWEs:       []string{"cwe-94", " CWE-78 ", "CWE-94"},
		Vulnrichment: &model.Vulnrichment{
			CWEs: []string{"CWE-94", "CWE-78"},
		},
	}

	got := EvaluateChainableEntrypoint(finding)
	if got.SourceFacts.CVSSSource != "scanner" || got.SourceFacts.CWESource != "vulnrichment" {
		t.Fatalf("sources = %q/%q, want scanner/vulnrichment", got.SourceFacts.CVSSSource, got.SourceFacts.CWESource)
	}
	if got.SourceFacts.AttackVector != "N" || got.SourceFacts.FullVulnerableSystemImpact {
		t.Fatalf("source facts = %#v, want AV:N and non-full impact", got.SourceFacts)
	}
	if want := []string{"CWE-78", "CWE-94"}; !reflect.DeepEqual(got.SourceFacts.CWEs, want) {
		t.Fatalf("source CWEs = %v, want %v", got.SourceFacts.CWEs, want)
	}
}
