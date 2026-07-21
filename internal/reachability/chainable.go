// Package reachability evaluates finding-level reachability metadata that is
// independent of provider exposure collection.
package reachability

import (
	"sort"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const (
	ChainableEntrypointPolicyVersion = "chainable-entrypoint-v2"

	ChainableEntrypointHighConfidence = "high_confidence"
	ChainableEntrypointPossible       = "possible"
	ChainableEntrypointNone           = "none"
)

var strictExecutionCWEs = map[string]struct{}{
	"CWE-78":  {},
	"CWE-94":  {},
	"CWE-95":  {},
	"CWE-96":  {},
	"CWE-98":  {},
	"CWE-553": {},
	"CWE-624": {},
	"CWE-917": {},
}

var combinedExecutionCWEs = map[string]struct{}{
	"CWE-97":  {},
	"CWE-494": {},
}

var contextDependentExecutionCWEs = map[string]struct{}{
	"CWE-829":  {},
	"CWE-1336": {},
}

var possibleExecutionCWEs = map[string]struct{}{
	"CWE-97":   {},
	"CWE-470":  {},
	"CWE-494":  {},
	"CWE-829":  {},
	"CWE-1336": {},
}

// EvaluateChainableEntrypoint applies the versioned E0 policy to one finding.
// The result flags potential upstream entry points only. It does not inspect
// deployment exposure or promote downstream findings.
func EvaluateChainableEntrypoint(finding model.Finding) *model.ChainableEntrypoint {
	metrics := parseVector(finding.CVSSVector)
	attackVector := metrics["AV"]
	fullImpact := hasFullVulnerableSystemImpact(finding.CVSSVector, metrics)
	cwes := normalizedCWEs(finding.CWEs)

	facts := model.ChainableEntrypointSourceFacts{
		CVSSVector:                 finding.CVSSVector,
		AttackVector:               attackVector,
		FullVulnerableSystemImpact: fullImpact,
		CWEs:                       cwes,
	}
	if finding.CVSSVector != "" {
		facts.CVSSSource = "scanner"
	}
	if len(cwes) > 0 {
		facts.CWESource = "finding"
		if finding.Vulnrichment != nil {
			facts.CWESource = "vulnrichment"
		}
	}

	result := &model.ChainableEntrypoint{
		Classification:  ChainableEntrypointNone,
		ActiveFinding:   !finding.Suppressed,
		CandidateStatus: ChainableEntrypointNone,
		PolicyVersion:   ChainableEntrypointPolicyVersion,
		SourceFacts:     facts,
	}

	if attackVector == "N" && intersects(cwes, strictExecutionCWEs) {
		result.CandidateStatus = ChainableEntrypointHighConfidence
		result.ReasonCodes = []string{"network-attack-vector", "strict-execution-cwe"}
		return result
	}

	if attackVector == "N" && fullImpact && intersects(cwes, combinedExecutionCWEs) {
		result.CandidateStatus = ChainableEntrypointHighConfidence
		result.ReasonCodes = []string{"network-attack-vector", "full-vulnerable-system-impact", "combined-execution-cwe"}
		return result
	}

	if attackVector == "N" && fullImpact && intersects(cwes, contextDependentExecutionCWEs) {
		result.CandidateStatus = ChainableEntrypointPossible
		result.ReasonCodes = []string{"network-attack-vector", "full-vulnerable-system-impact", "execution-context-required"}
		result.ExecutionContext = "unknown"
		result.ExecutionContextSource = "not-collected"
		return result
	}

	if attackVector == "N" && (fullImpact || intersects(cwes, possibleExecutionCWEs)) {
		result.CandidateStatus = ChainableEntrypointPossible
		if fullImpact {
			result.ReasonCodes = append(result.ReasonCodes, "full-impact-without-execution-signal")
		}
		if attackVector == "N" && intersects(cwes, possibleExecutionCWEs) {
			result.ReasonCodes = append(result.ReasonCodes, "possible-execution-cwe")
		}
		if intersects(cwes, contextDependentExecutionCWEs) {
			result.ReasonCodes = append(result.ReasonCodes, "execution-context-required")
			result.ExecutionContext = "unknown"
			result.ExecutionContextSource = "not-collected"
		}
		return result
	}

	switch {
	case attackVector == "":
		result.ReasonCodes = []string{"attack-vector-unavailable"}
	case attackVector != "N":
		result.ReasonCodes = []string{"attack-vector-not-network"}
	case len(cwes) == 0:
		result.ReasonCodes = []string{"execution-signal-unavailable"}
	default:
		result.ReasonCodes = []string{"no-chainable-execution-signal"}
	}
	return result
}

// ClassifyChainableEntrypoint joins the CVE-level E0 candidate classification to
// the deployed finding's active state and the affected asset's internet exposure.
// It deliberately stops at the upstream entry-point flag and performs no G0 join
// or downstream vulnerability promotion.
func ClassifyChainableEntrypoint(value *model.ChainableEntrypoint, internetAccessible bool) *model.ChainableEntrypoint {
	if value == nil {
		return nil
	}
	result := *value
	result.ReasonCodes = append([]string(nil), value.ReasonCodes...)
	result.SourceFacts.CWEs = append([]string(nil), value.SourceFacts.CWEs...)
	result.InternetAccessible = internetAccessible
	result.HighConfidence = false
	result.Classification = ChainableEntrypointNone
	result.ClassificationReasonCodes = nil

	if !result.ActiveFinding {
		result.ClassificationReasonCodes = append(result.ClassificationReasonCodes, "finding-not-active")
	}
	if !result.InternetAccessible {
		result.ClassificationReasonCodes = append(result.ClassificationReasonCodes, "asset-not-internet-accessible")
	}
	if !result.ActiveFinding || !result.InternetAccessible {
		return &result
	}

	switch result.CandidateStatus {
	case ChainableEntrypointHighConfidence:
		result.Classification = ChainableEntrypointHighConfidence
		result.HighConfidence = true
		result.ClassificationReasonCodes = []string{"active-finding", "asset-internet-accessible", "high-confidence-candidate"}
	case ChainableEntrypointPossible:
		result.Classification = ChainableEntrypointPossible
		result.ClassificationReasonCodes = []string{"active-finding", "asset-internet-accessible", "possible-candidate"}
	default:
		result.ClassificationReasonCodes = []string{"active-finding", "asset-internet-accessible", "no-chainable-candidate"}
	}
	return &result
}

func parseVector(vector string) map[string]string {
	metrics := map[string]string{}
	for _, token := range strings.Split(vector, "/") {
		key, value, ok := strings.Cut(token, ":")
		if !ok {
			continue
		}
		metrics[strings.ToUpper(strings.TrimSpace(key))] = strings.ToUpper(strings.TrimSpace(value))
	}
	return metrics
}

func hasFullVulnerableSystemImpact(vector string, metrics map[string]string) bool {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(vector)), "CVSS:4") {
		return metrics["VC"] == "H" && metrics["VI"] == "H" && metrics["VA"] == "H"
	}
	return metrics["C"] == "H" && metrics["I"] == "H" && metrics["A"] == "H"
}

func normalizedCWEs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func intersects(values []string, set map[string]struct{}) bool {
	for _, value := range values {
		if _, ok := set[value]; ok {
			return true
		}
	}
	return false
}
