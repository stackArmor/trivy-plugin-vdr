package report

import (
	"sort"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

// dedupeKey identifies findings that describe the same vulnerability in the
// same package version, regardless of which image or scan target surfaced them.
type dedupeKey struct {
	ID               string
	PackageName      string
	InstalledVersion string
}

func findingDedupeKey(finding model.Finding) dedupeKey {
	return dedupeKey{
		ID:               finding.ID,
		PackageName:      finding.PackageName,
		InstalledVersion: finding.InstalledVersion,
	}
}

// uniqueResourceRefs returns refs with duplicates removed, preserving the order
// of first appearance.
func uniqueResourceRefs(refs []model.ResourceRef) []model.ResourceRef {
	if len(refs) == 0 {
		return nil
	}
	seen := make(map[model.ResourceRef]struct{}, len(refs))
	unique := make([]model.ResourceRef, 0, len(refs))
	for _, ref := range refs {
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		unique = append(unique, ref)
	}
	return unique
}

// dedupeFindings merges findings that share a dedupeKey into a single record.
// The first occurrence in input order survives (findings arrive sorted from
// filterFindings, so the survivor is deterministic); later occurrences
// contribute their AffectedResources and ImageRef. ImageRefs is populated only
// when the merged duplicates span more than one distinct image.
func dedupeFindings(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return nil
	}
	merged := make([]model.Finding, 0, len(findings))
	index := make(map[dedupeKey]int, len(findings))
	images := make([]map[string]struct{}, 0, len(findings))
	for _, finding := range findings {
		key := findingDedupeKey(finding)
		at, ok := index[key]
		if !ok {
			index[key] = len(merged)
			merged = append(merged, cloneFinding(finding))
			refs := map[string]struct{}{}
			if finding.ImageRef != "" {
				refs[finding.ImageRef] = struct{}{}
			}
			images = append(images, refs)
			continue
		}
		merged[at].AffectedResources = append(merged[at].AffectedResources, finding.AffectedResources...)
		if chainableEntrypointRank(finding.ChainableEntrypoint) > chainableEntrypointRank(merged[at].ChainableEntrypoint) {
			merged[at].ChainableEntrypoint = cloneChainableEntrypoint(finding.ChainableEntrypoint)
		}
		if finding.ImageRef != "" {
			images[at][finding.ImageRef] = struct{}{}
		}
	}
	for i := range merged {
		merged[i].AffectedResources = uniqueResourceRefs(merged[i].AffectedResources)
		if len(images[i]) < 2 {
			continue
		}
		refs := make([]string, 0, len(images[i]))
		for ref := range images[i] {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		merged[i].ImageRefs = refs
	}
	return merged
}

// chainableEntrypointRank makes deduplication conservative when two scanner
// records for the same CVE/package version carry different source metadata.
func chainableEntrypointRank(value *model.ChainableEntrypoint) int {
	if value == nil {
		return 0
	}
	switch value.CandidateStatus {
	case "high-confidence":
		return 3
	case "possible":
		return 2
	case "none":
		return 1
	default:
		return 0
	}
}
