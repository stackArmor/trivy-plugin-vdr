package chainanalysis

import (
	"sort"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/chaincatalog"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const (
	CAPECTransitionPolicyVersion  = "capec-transition-v1"
	CAPECTransitionEvidenceLevel  = "pattern_level_candidate"
	CAPECTransitionClass          = "external_to_follow_on"
	CAPECTransitionEntrypointRole = "candidate_entrypoint"
	CAPECTransitionFollowerRole   = "candidate_follower"
)

// FindReportTransitions finds explicit CAPEC P CanPrecede Q pairs between
// distinct active findings on the same exact resource. Resource-view findings
// are already scoped. Finding-view reports are regrouped through affected[].
func FindReportTransitions(findings []model.Finding, resources []model.ResourceReport, catalog *chaincatalog.Catalog) []model.CAPECTransitionCandidate {
	if catalog == nil {
		return nil
	}
	var transitions []model.CAPECTransitionCandidate
	if len(resources) > 0 {
		for _, resource := range resources {
			transitions = append(transitions, FindResourceTransitions(
				resource.Resource,
				internetAccessible(resource.Exposure),
				resource.Findings,
				catalog,
			)...)
		}
		return sortedTransitions(transitions)
	}

	type bucket struct {
		resource           model.ResourceRef
		internetAccessible bool
		findings           []model.Finding
	}
	buckets := map[model.ResourceRef]*bucket{}
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		if len(finding.Affected) > 0 {
			for _, affected := range finding.Affected {
				current := buckets[affected.Resource]
				if current == nil {
					current = &bucket{resource: affected.Resource}
					buckets[affected.Resource] = current
				}
				current.internetAccessible = current.internetAccessible || internetAccessible(affected.Exposure)
				current.findings = append(current.findings, finding)
			}
			continue
		}
		for _, resource := range finding.AffectedResources {
			current := buckets[resource]
			if current == nil {
				current = &bucket{resource: resource}
				buckets[resource] = current
			}
			current.internetAccessible = current.internetAccessible || internetAccessible(finding.Exposure)
			current.findings = append(current.findings, finding)
		}
	}
	for _, current := range buckets {
		transitions = append(transitions, FindResourceTransitions(
			current.resource,
			current.internetAccessible,
			current.findings,
			catalog,
		)...)
	}
	return sortedTransitions(transitions)
}

// FindResourceTransitions finds explicit CAPEC edges from an externally
// triggerable CVE to any downstream CVE on one exact internet-reachable
// resource/container. The downstream CVSS access metrics are context, not an
// eligibility gate. Package occurrences and alternate CWE paths are aggregated
// by resource, CVE pair, and CAPEC edge.
func FindResourceTransitions(resource model.ResourceRef, exposed bool, findings []model.Finding, catalog *chaincatalog.Catalog) []model.CAPECTransitionCandidate {
	if catalog == nil || len(findings) < 2 || !exposed {
		return nil
	}
	byKey := map[string]int{}
	var result []model.CAPECTransitionCandidate
	for upstreamIndex := range findings {
		upstream := findings[upstreamIndex]
		if upstream.Suppressed || upstream.ChainTaxonomy == nil || upstream.ChainTaxonomy.Status != StatusMapped {
			continue
		}
		upstreamAV := cvssMetric(upstream.CVSSVector, "AV")
		upstreamPR := cvssMetric(upstream.CVSSVector, "PR")
		if upstreamAV != "N" || upstreamPR != "N" {
			continue
		}
		for downstreamIndex := range findings {
			downstream := findings[downstreamIndex]
			if upstreamIndex == downstreamIndex || downstream.Suppressed || upstream.ID == downstream.ID ||
				downstream.ChainTaxonomy == nil || downstream.ChainTaxonomy.Status != StatusMapped {
				continue
			}
			for _, sourcePath := range upstream.ChainTaxonomy.Paths {
				if len(sourcePath.SuccessorCAPECIDs) == 0 {
					continue
				}
				successors := stringSet(sourcePath.SuccessorCAPECIDs)
				for _, targetPath := range downstream.ChainTaxonomy.Paths {
					if _, ok := successors[targetPath.CAPECID]; !ok {
						continue
					}
					key := transitionKey(resource, upstream, downstream, sourcePath, targetPath)
					if existingIndex, duplicate := byKey[key]; duplicate {
						existing := &result[existingIndex]
						addTransitionEndpointEvidence(&existing.Upstream, upstream, sourcePath.CWEID)
						addTransitionEndpointEvidence(&existing.Downstream, downstream, targetPath.CWEID)
						continue
					}
					sourcePattern, _ := catalog.Pattern(sourcePath.CAPECID)
					targetPattern, _ := catalog.Pattern(targetPath.CAPECID)
					result = append(result, model.CAPECTransitionCandidate{
						Resource:                   resource,
						CandidateClass:             CAPECTransitionClass,
						Upstream:                   transitionEndpoint(upstream, sourcePath.CWEID, CAPECTransitionEntrypointRole),
						Downstream:                 transitionEndpoint(downstream, targetPath.CWEID, CAPECTransitionFollowerRole),
						SourceCAPECID:              sourcePath.CAPECID,
						SourceCAPECName:            sourcePath.CAPECName,
						TargetCAPECID:              targetPath.CAPECID,
						TargetCAPECName:            targetPath.CAPECName,
						Relationship:               "CanPrecede",
						UpstreamInternetAccessible: exposed,
						SourceConsequenceImpacts:   consequenceImpacts(sourcePattern),
						TargetPrerequisites:        append([]string(nil), targetPattern.Prerequisites...),
						EvidenceLevel:              CAPECTransitionEvidenceLevel,
						Confidence:                 "low",
						ReviewRequired:             true,
						ReasonCodes: []string{
							"same-exact-resource",
							"upstream-resource-internet-accessible",
							"upstream-network-attack-vector",
							"upstream-no-privileges-required",
							"explicit-capec-can-precede",
							"cwe-capec-path-on-both-findings",
						},
						PolicyVersion: CAPECTransitionPolicyVersion,
					})
					byKey[key] = len(result) - 1
				}
			}
		}
	}
	return sortedTransitions(result)
}

// AddTransitionSummary adds report-level transition counts to an existing
// taxonomy coverage summary.
func AddTransitionSummary(summary *model.ChainTaxonomySummary, transitions []model.CAPECTransitionCandidate) {
	if summary == nil {
		return
	}
	summary.TransitionCandidates = len(transitions)
	resources := map[model.ResourceRef]struct{}{}
	entrypoints := map[string]struct{}{}
	entrypointCVEs := map[string]struct{}{}
	for _, transition := range transitions {
		resources[transition.Resource] = struct{}{}
		entrypoints[resourceEntrypointKey(transition.Resource, transition.Upstream.ID)] = struct{}{}
		entrypointCVEs[transition.Upstream.ID] = struct{}{}
	}
	summary.EntrypointCandidates = len(entrypoints)
	summary.UniqueEntrypointCVEs = len(entrypointCVEs)
	summary.ResourcesWithTransitions = len(resources)
}

func transitionEndpoint(finding model.Finding, cweID, role string) model.CAPECTransitionEndpoint {
	return model.CAPECTransitionEndpoint{
		ID:                 finding.ID,
		Role:               role,
		Findings:           []model.CAPECTransitionFindingReference{transitionFindingReference(finding)},
		CWEIDs:             []string{cweID},
		AttackVector:       cvssMetric(finding.CVSSVector, "AV"),
		PrivilegesRequired: cvssMetric(finding.CVSSVector, "PR"),
	}
}

func resourceEntrypointKey(resource model.ResourceRef, cveID string) string {
	return strings.Join([]string{
		resource.APIVersion,
		resource.Provider,
		resource.Project,
		resource.Region,
		resource.Namespace,
		resource.Kind,
		resource.Name,
		resource.ContainerName,
		resource.ContainerType,
		cveID,
	}, "\x00")
}

func transitionFindingReference(finding model.Finding) model.CAPECTransitionFindingReference {
	return model.CAPECTransitionFindingReference{
		PackageName:      finding.PackageName,
		InstalledVersion: finding.InstalledVersion,
		ImageRef:         finding.ImageRef,
	}
}

func addTransitionEndpointEvidence(endpoint *model.CAPECTransitionEndpoint, finding model.Finding, cweID string) {
	endpoint.CWEIDs = appendUniqueSorted(endpoint.CWEIDs, cweID)
	reference := transitionFindingReference(finding)
	key := findingReferenceKey(reference)
	for _, existing := range endpoint.Findings {
		if findingReferenceKey(existing) == key {
			return
		}
	}
	endpoint.Findings = append(endpoint.Findings, reference)
	sort.Slice(endpoint.Findings, func(i, j int) bool {
		return findingReferenceKey(endpoint.Findings[i]) < findingReferenceKey(endpoint.Findings[j])
	})
}

func appendUniqueSorted(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	sort.Strings(values)
	return values
}

func findingReferenceKey(value model.CAPECTransitionFindingReference) string {
	return strings.Join([]string{value.PackageName, value.InstalledVersion, value.ImageRef}, "\x00")
}

func transitionKey(resource model.ResourceRef, upstream, downstream model.Finding, source, target model.ChainTaxonomyPath) string {
	return strings.Join([]string{
		resource.APIVersion,
		resource.Provider,
		resource.Project,
		resource.Region,
		resource.Namespace,
		resource.Kind,
		resource.Name,
		resource.ContainerName,
		resource.ContainerType,
		upstream.ID,
		source.CAPECID,
		downstream.ID,
		target.CAPECID,
	}, "\x00")
}

func sortedTransitions(values []model.CAPECTransitionCandidate) []model.CAPECTransitionCandidate {
	sort.Slice(values, func(i, j int) bool {
		left := transitionSortKey(values[i])
		right := transitionSortKey(values[j])
		return left < right
	})
	return values
}

func transitionSortKey(value model.CAPECTransitionCandidate) string {
	return strings.Join([]string{
		value.Resource.Provider,
		value.Resource.Project,
		value.Resource.Region,
		value.Resource.Namespace,
		value.Resource.Kind,
		value.Resource.Name,
		value.Resource.ContainerName,
		value.Upstream.ID,
		value.SourceCAPECID,
		value.Downstream.ID,
		value.TargetCAPECID,
	}, "\x00")
}

func consequenceImpacts(pattern chaincatalog.Pattern) []string {
	set := map[string]struct{}{}
	for _, consequence := range pattern.Consequences {
		if value := strings.TrimSpace(consequence.Impact); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func internetAccessible(exposure *model.Exposure) bool {
	return exposure != nil && exposure.InternetAccessible
}

func cvssMetric(vector, metric string) string {
	metric = strings.ToUpper(strings.TrimSpace(metric))
	for _, token := range strings.Split(vector, "/") {
		key, value, ok := strings.Cut(token, ":")
		if ok && strings.ToUpper(strings.TrimSpace(key)) == metric {
			return strings.ToUpper(strings.TrimSpace(value))
		}
	}
	return ""
}
