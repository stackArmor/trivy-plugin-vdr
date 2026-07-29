// Package chainanalysis projects offline CAPEC and ATT&CK taxonomy evidence
// onto vulnerability findings. The v1 policy is informational only.
package chainanalysis

import (
	"sort"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/chaincatalog"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const TaxonomyPolicyVersion = "chain-taxonomy-v1"

const (
	StatusMapped  = "mapped"
	StatusUnknown = "unknown"

	RoleProducer = "producer_candidate"
	RoleConsumer = "consumer_candidate"
	RoleBridge   = "bridge_candidate"
	RoleIsolated = "isolated_in_capec"
	RoleUnknown  = "unknown"

	RelationPresent     = "present"
	RelationNotDeclared = "not_declared"
	RelationUnknown     = "unknown"
)

// AnnotateFindings applies the taxonomy policy to every finding in place.
func AnnotateFindings(findings []model.Finding, catalog *chaincatalog.Catalog) {
	for i := range findings {
		findings[i].ChainTaxonomy = ClassifyTaxonomy(findings[i], catalog)
	}
}

// SummarizeTaxonomy reports coverage over the supplied findings.
func SummarizeTaxonomy(findings []model.Finding) *model.ChainTaxonomySummary {
	if len(findings) == 0 {
		return nil
	}
	summary := &model.ChainTaxonomySummary{}
	hasTaxonomy := false
	for _, finding := range findings {
		if finding.ChainTaxonomy == nil {
			continue
		}
		hasTaxonomy = true
		switch finding.ChainTaxonomy.Status {
		case StatusMapped:
			summary.MappedFindings++
		default:
			summary.UnknownFindings++
		}
		if finding.ChainTaxonomy.Ambiguity != "" && finding.ChainTaxonomy.Ambiguity != "none" {
			summary.AmbiguousFindings++
		}
		if len(finding.ChainTaxonomy.ATTACKTechniqueIDs) > 0 {
			summary.FindingsWithATTACKTechnique++
		}
		if len(finding.ChainTaxonomy.PredecessorCAPECIDs) > 0 {
			summary.FindingsWithExplicitPredecessor++
		}
		if len(finding.ChainTaxonomy.SuccessorCAPECIDs) > 0 {
			summary.FindingsWithExplicitSuccessor++
		}
	}
	if !hasTaxonomy {
		return nil
	}
	return summary
}

// ClassifyTaxonomy preserves every eligible CWE -> CAPEC path and derives a
// coarse pattern-level role from CAPEC's explicit CanPrecede/CanFollow edges.
// Absence of a mapping or edge is reported as unknown/isolated evidence, never
// as proof that a CVE cannot participate in an attack chain.
func ClassifyTaxonomy(finding model.Finding, catalog *chaincatalog.Catalog) *model.ChainTaxonomyEvidence {
	result := &model.ChainTaxonomyEvidence{
		Status:            StatusUnknown,
		TaxonomyRole:      RoleUnknown,
		Ambiguity:         "none",
		PredecessorStatus: RelationUnknown,
		SuccessorStatus:   RelationUnknown,
		PolicyVersion:     TaxonomyPolicyVersion,
	}
	cwes := normalizedCWEs(finding.CWEs)
	if len(cwes) == 0 {
		result.ReasonCodes = []string{"no-specific-cwe"}
		return result
	}
	if catalog == nil {
		result.ReasonCodes = []string{"chain-catalog-unavailable"}
		return result
	}

	patterns := catalog.PatternsForCWEs(cwes)
	if len(patterns) == 0 {
		result.ReasonCodes = []string{"no-eligible-capec-pattern"}
		return result
	}

	cweSet := make(map[string]struct{}, len(cwes))
	for _, cwe := range cwes {
		cweSet[cwe] = struct{}{}
	}
	roleSet := map[string]struct{}{}
	capecIDs := map[string]struct{}{}
	techniqueIDs := map[string]struct{}{}
	tactics := map[string]struct{}{}
	predecessors := map[string]struct{}{}
	successors := map[string]struct{}{}

	for _, pattern := range patterns {
		matchedCWEs := intersectStrings(pattern.CWEs, cweSet)
		for _, cwe := range matchedCWEs {
			path := model.ChainTaxonomyPath{
				CWEID:               cwe,
				CAPECID:             pattern.ID,
				CAPECName:           pattern.Name,
				Abstraction:         pattern.Abstraction,
				PredecessorCAPECIDs: append([]string(nil), pattern.Predecessors...),
				SuccessorCAPECIDs:   append([]string(nil), pattern.Successors...),
			}
			for _, technique := range pattern.Techniques {
				path.ATTACKTechniques = append(path.ATTACKTechniques, model.ChainATTACKTechnique{
					ID:      technique.ID,
					Name:    technique.Name,
					Tactics: append([]string(nil), technique.Tactics...),
				})
				techniqueIDs[technique.ID] = struct{}{}
				for _, tactic := range technique.Tactics {
					tactics[tactic] = struct{}{}
				}
			}
			for _, consequence := range pattern.Consequences {
				if consequence.Impact != "" {
					path.ConsequenceImpacts = append(path.ConsequenceImpacts, consequence.Impact)
				}
			}
			path.ConsequenceImpacts = sortedSet(path.ConsequenceImpacts)
			result.Paths = append(result.Paths, path)
		}
		capecIDs[pattern.ID] = struct{}{}
		for _, id := range pattern.Predecessors {
			predecessors[id] = struct{}{}
		}
		for _, id := range pattern.Successors {
			successors[id] = struct{}{}
		}
		roleSet[pathRole(len(pattern.Predecessors) > 0, len(pattern.Successors) > 0)] = struct{}{}
	}

	sort.Slice(result.Paths, func(i, j int) bool {
		if result.Paths[i].CWEID != result.Paths[j].CWEID {
			return result.Paths[i].CWEID < result.Paths[j].CWEID
		}
		return result.Paths[i].CAPECID < result.Paths[j].CAPECID
	})
	result.Status = StatusMapped
	result.CAPECIDs = keys(capecIDs)
	result.ATTACKTechniqueIDs = keys(techniqueIDs)
	result.ATTACKTactics = keys(tactics)
	result.PredecessorCAPECIDs = keys(predecessors)
	result.SuccessorCAPECIDs = keys(successors)
	result.PredecessorStatus = relationStatus(len(result.PredecessorCAPECIDs) > 0)
	result.SuccessorStatus = relationStatus(len(result.SuccessorCAPECIDs) > 0)
	result.TaxonomyRole = aggregateRole(len(predecessors) > 0, len(successors) > 0)
	result.ReasonCodes = append(result.ReasonCodes, "capec-mapped")
	if len(result.ATTACKTechniqueIDs) > 0 {
		result.ReasonCodes = append(result.ReasonCodes, "attack-technique-mapped")
	}
	if len(result.PredecessorCAPECIDs) > 0 {
		result.ReasonCodes = append(result.ReasonCodes, "explicit-capec-predecessor")
	}
	if len(result.SuccessorCAPECIDs) > 0 {
		result.ReasonCodes = append(result.ReasonCodes, "explicit-capec-successor")
	}
	if len(result.Paths) > 1 {
		result.Ambiguity = "multiple_paths"
		result.ReasonCodes = append(result.ReasonCodes, "multiple-capec-paths")
	}
	if len(roleSet) > 1 {
		result.Ambiguity = "mixed_roles"
		result.ReasonCodes = append(result.ReasonCodes, "mixed-capec-roles")
	}
	return result
}

// CatalogMetadata converts runtime catalog provenance into the public report
// model without exposing catalog internals to the report package.
func CatalogMetadata(catalog *chaincatalog.Catalog) *model.ChainCatalogMetadata {
	if catalog == nil {
		return nil
	}
	sources := catalog.Sources()
	return &model.ChainCatalogMetadata{
		SchemaVersion: chaincatalog.SchemaVersion,
		CAPECVersion:  sources.CAPECVersion,
		CAPECDate:     sources.CAPECDate,
		CAPECSHA256:   sources.CAPECSHA256,
		ATTACKVersion: sources.ATTACKVersion,
		ATTACKDate:    sources.ATTACKDate,
		ATTACKSHA256:  sources.ATTACKSHA256,
	}
}

func normalizedCWEs(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if !strings.HasPrefix(value, "CWE-") {
			value = "CWE-" + value
		}
		set[value] = struct{}{}
	}
	return keys(set)
}

func intersectStrings(values []string, set map[string]struct{}) []string {
	var result []string
	for _, value := range values {
		if _, ok := set[value]; ok {
			result = append(result, value)
		}
	}
	return sortedSet(result)
}

func pathRole(incoming, outgoing bool) string {
	return aggregateRole(incoming, outgoing)
}

func relationStatus(present bool) string {
	if present {
		return RelationPresent
	}
	return RelationNotDeclared
}

func aggregateRole(incoming, outgoing bool) string {
	switch {
	case incoming && outgoing:
		return RoleBridge
	case outgoing:
		return RoleProducer
	case incoming:
		return RoleConsumer
	default:
		return RoleIsolated
	}
}

func sortedSet(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	return keys(set)
}

func keys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
