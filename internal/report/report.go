package report

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scoring"
)

const (
	ViewFindings  = "findings"
	ViewResources = "resources"
)

type Options struct {
	GeneratedAt time.Time
	View        string
	MinSeverity string
	MinEPSS     float64
	Warnings    []string
	// Scoring is the FedRAMP PAIN rubric. When nil, the built-in default rubric
	// (scoring.Default) is used.
	Scoring *scoring.Config
}

func Build(inventory *model.Inventory, findings []model.Finding, exposures map[model.ResourceRef]model.Exposure, options Options) model.Report {
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = time.Now().UTC()
	}
	if options.View == "" {
		options.View = ViewFindings
	}
	sc := options.Scoring
	if sc == nil {
		sc = scoring.Default()
	}
	labelIndex := workloadLabelIndex(inventory)
	nsLabels := map[string]map[string]string{}
	if inventory != nil && inventory.Namespaces != nil {
		nsLabels = inventory.Namespaces
	}

	class := sc.Defaults.Class
	if class == "" {
		class = "B"
	}
	contextName := ""
	if inventory != nil {
		contextName = inventory.ContextName
	}

	filtered := filterFindings(findings, options.MinSeverity, options.MinEPSS)
	active, suppressed := partitionFindings(filtered)
	resourceReports := buildResourceReports(inventory, active, exposures, sc, labelIndex, nsLabels)
	report := model.Report{
		GeneratedAt:        options.GeneratedAt,
		ContextName:        contextName,
		Class:              class,
		Summary:            buildSummary(inventory, active, resourceReports),
		SuppressedFindings: suppressedWithWouldHaveBeen(suppressed, exposures, sc, labelIndex, nsLabels),
		Warnings:           append([]string(nil), options.Warnings...),
	}
	if options.View == ViewResources {
		report.Resources = resourceReports
		return report
	}

	report.Findings = findingsWithBestExposure(active, exposures, sc, labelIndex, nsLabels)
	return report
}

func partitionFindings(findings []model.Finding) ([]model.Finding, []model.Finding) {
	var active []model.Finding
	var suppressed []model.Finding
	for _, finding := range findings {
		if finding.Suppressed {
			suppressed = append(suppressed, finding)
			continue
		}
		active = append(active, finding)
	}
	return active, suppressed
}

// workloadLabelIndex maps a workload identity (namespace/kind/name) to its merged
// labels, so PAIN scoring can resolve an asset's archetype from the labels of the
// workload that owns an affected (container-level) resource reference.
func workloadLabelIndex(inventory *model.Inventory) map[string]map[string]string {
	index := map[string]map[string]string{}
	if inventory == nil {
		return index
	}
	for _, r := range inventory.Resources {
		index[workloadLabelKey(r.Resource)] = r.Labels
	}
	return index
}

func workloadLabelKey(ref model.ResourceRef) string {
	return ref.Namespace + "\x00" + ref.Kind + "\x00" + ref.Name
}

// scoreAsset computes the PAIN and FedRAMP remediation deadline for a finding on
// a specific resource, given that resource's internet reachability.
func scoreAsset(sc *scoring.Config, idx, nsLabels map[string]map[string]string, ref model.ResourceRef, finding model.Finding, internetReachable bool) (*model.Pain, *model.Remediation) {
	res := sc.Score(scoring.Input{
		CVSSVector:        finding.CVSSVector,
		Severity:          finding.Severity,
		Namespace:         ref.Namespace,
		WorkloadName:      ref.Name,
		Labels:            idx[workloadLabelKey(ref)],
		NamespaceLabels:   nsLabels[ref.Namespace],
		TechnicalImpact:   technicalImpactOf(finding.Vulnrichment),
		EPSS:              epssScore(finding.EPSS),
		Exploitation:      exploitationOf(finding.Vulnrichment),
		InternetReachable: internetReachable,
	})
	pain := &model.Pain{
		Tier:            res.Tier,
		Word:            res.Word,
		Severity:        res.Severity,
		Archetype:       res.Archetype,
		ArchetypeSource: res.ArchetypeSource,
		SeveritySource:  res.SeveritySource,
		CR:              res.CR,
		IR:              res.IR,
		AR:              res.AR,
		MultiAgency:     res.MultiAgency,
	}
	rem := &model.Remediation{
		Class:        res.Class,
		Column:       res.Column,
		LEV:          res.LEV,
		IRV:          res.IRV,
		DeadlineDays: res.DeadlineDays,
		Deadline:     res.RemediationLabel,
	}
	return pain, rem
}

func epssScore(e *model.EPSS) float64 {
	if e == nil {
		return -1
	}
	return e.Score
}

func exploitationOf(v *model.Vulnrichment) string {
	if v == nil {
		return ""
	}
	return v.Exploitation
}

func technicalImpactOf(v *model.Vulnrichment) string {
	if v == nil {
		return ""
	}
	return v.TechnicalImpact
}

func internetReachable(exposure *model.Exposure) bool {
	return exposure != nil && exposure.InternetAccessible
}

func RenderJSON(w io.Writer, report model.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func RenderTable(w io.Writer, report model.Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(report.Resources) > 0 {
		if _, err := fmt.Fprintln(tw, "NAMESPACE\tRESOURCE\tCONTAINER\tIMAGE\tEXPOSED\tPAIN\tREMEDIATION\tFINDINGS"); err != nil {
			return err
		}
		for _, resource := range report.Resources {
			if _, err := fmt.Fprintf(tw, "%s\t%s/%s\t%s\t%s\t%s\t%s\t%s\t%d\n",
				resource.Resource.Namespace,
				resource.Resource.Kind,
				resource.Resource.Name,
				resource.Resource.ContainerName,
				formatResourceImages(resource.Images),
				formatExposure(resource.Exposure),
				worstPainTier(resource.Findings),
				soonestRemediation(resource.Findings),
				len(resource.Findings),
			); err != nil {
				return err
			}
		}
		if err := renderSuppressedTable(tw, report.SuppressedFindings); err != nil {
			return err
		}
		return tw.Flush()
	}
	if _, err := fmt.Fprintln(tw, "ID\tSEVERITY\tSTATUS\tPAIN\tREMEDIATION\tEPSS\tAUTOMATABLE\tEXPLOITATION\tTECHNICAL IMPACT\tIMAGE\tAFFECTED"); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			finding.ID,
			finding.Severity,
			finding.Status,
			formatPain(finding.Pain),
			formatRemediation(finding.Remediation),
			formatEPSS(finding.EPSS),
			vulnrichmentValue(finding.Vulnrichment, "automatable"),
			vulnrichmentValue(finding.Vulnrichment, "exploitation"),
			vulnrichmentValue(finding.Vulnrichment, "technicalImpact"),
			finding.ImageRef,
			formatAffectedResources(finding.AffectedResources),
		); err != nil {
			return err
		}
	}
	if err := renderSuppressedTable(tw, report.SuppressedFindings); err != nil {
		return err
	}
	return tw.Flush()
}

func renderSuppressedTable(w io.Writer, findings []model.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nSUPPRESSED FINDINGS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "ID\tSEVERITY\tVEX STATUS\tJUSTIFICATION\tWOULD-HAVE-BEEN PAIN\tWOULD-HAVE-BEEN REMEDIATION\tIMAGE\tAFFECTED"); err != nil {
		return err
	}
	for _, finding := range findings {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			finding.ID,
			finding.Severity,
			suppressionStatus(finding.Suppression),
			suppressionJustification(finding.Suppression),
			formatPain(finding.WouldHaveBeenPain),
			formatRemediation(finding.WouldHaveBeenRemediation),
			finding.ImageRef,
			formatAffectedResources(finding.AffectedResources),
		); err != nil {
			return err
		}
	}
	return nil
}

func filterFindings(findings []model.Finding, minSeverity string, minEPSS float64) []model.Finding {
	var filtered []model.Finding
	for _, finding := range findings {
		if !severityAtLeast(finding.Severity, minSeverity) {
			continue
		}
		if minEPSS >= 0 {
			if finding.EPSS == nil || finding.EPSS.Score < minEPSS {
				continue
			}
		}
		filtered = append(filtered, cloneFinding(finding))
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].ID != filtered[j].ID {
			return filtered[i].ID < filtered[j].ID
		}
		if filtered[i].ImageRef != filtered[j].ImageRef {
			return filtered[i].ImageRef < filtered[j].ImageRef
		}
		return filtered[i].PackageName < filtered[j].PackageName
	})
	return filtered
}

func buildResourceReports(inventory *model.Inventory, findings []model.Finding, exposures map[model.ResourceRef]model.Exposure, sc *scoring.Config, idx, nsLabels map[string]map[string]string) []model.ResourceReport {
	if inventory == nil {
		return nil
	}
	reports := map[model.ResourceRef]*model.ResourceReport{}
	for ref, inv := range indexContainerInventory(inventory) {
		report := &model.ResourceReport{
			Resource: ref,
			Images:   append([]model.ContainerImage(nil), inv.images...),
			Labels:   copyStringMap(inv.labels),
		}
		if exposure, ok := exposures[ref]; ok {
			value := exposure
			report.Exposure = &value
		}
		reports[ref] = report
	}
	for _, finding := range findings {
		for _, ref := range finding.AffectedResources {
			report := reports[ref]
			if report == nil {
				report = &model.ResourceReport{Resource: ref}
				if exposure, ok := exposures[ref]; ok {
					value := exposure
					report.Exposure = &value
				}
				reports[ref] = report
			}
			scoped := cloneFinding(finding)
			scoped.AffectedResources = []model.ResourceRef{ref}
			scoped.Affected = []model.Affected{{Resource: ref}}
			if exposure, ok := exposures[ref]; ok {
				value := exposure
				scoped.Exposure = &value
				scoped.Affected[0].Exposure = &value
			}
			pain, rem := scoreAsset(sc, idx, nsLabels, ref, finding, internetReachable(scoped.Exposure))
			scoped.Pain = pain
			scoped.Remediation = rem
			scoped.Affected[0].Pain = pain
			scoped.Affected[0].Remediation = rem
			report.Findings = append(report.Findings, scoped)
		}
	}

	keys := make([]model.ResourceRef, 0, len(reports))
	for ref := range reports {
		keys = append(keys, ref)
	}
	sort.Slice(keys, func(i, j int) bool {
		return resourceSortKey(keys[i]) < resourceSortKey(keys[j])
	})
	result := make([]model.ResourceReport, 0, len(keys))
	for _, key := range keys {
		result = append(result, *reports[key])
	}
	return result
}

type containerInventory struct {
	images []model.ContainerImage
	labels map[string]string
}

func indexContainerInventory(inventory *model.Inventory) map[model.ResourceRef]containerInventory {
	index := map[model.ResourceRef]containerInventory{}
	for _, resource := range inventory.Resources {
		for _, image := range resource.Images {
			ref := resource.Resource
			ref.ContainerName = image.Name
			ref.ContainerType = image.ContainerType
			ref.RestartPolicy = image.RestartPolicy
			index[ref] = containerInventory{
				images: []model.ContainerImage{image},
				labels: copyStringMap(resource.Labels),
			}
		}
	}
	return index
}

func buildSummary(inventory *model.Inventory, findings []model.Finding, resources []model.ResourceReport) model.Summary {
	summary := model.Summary{BySeverity: map[string]int{}}
	if inventory != nil {
		summary.Resources = len(inventory.Resources)
		summary.Images = len(inventory.Images)
		namespaces := map[string]struct{}{}
		if inventory.ContextName != "" {
			summary.Contexts = 1
		}
		for _, resource := range inventory.Resources {
			if resource.Resource.Namespace != "" {
				namespaces[resource.Resource.Namespace] = struct{}{}
			}
		}
		summary.Namespaces = len(namespaces)
	}
	summary.Findings = len(findings)
	for _, finding := range findings {
		summary.BySeverity[finding.Severity]++
	}
	for _, resource := range resources {
		if resource.Exposure != nil && resource.Exposure.InternetAccessible {
			summary.InternetAccessible++
		}
	}
	return summary
}

func findingsWithBestExposure(findings []model.Finding, exposures map[model.ResourceRef]model.Exposure, sc *scoring.Config, idx, nsLabels map[string]map[string]string) []model.Finding {
	enriched := make([]model.Finding, len(findings))
	for i, finding := range findings {
		enriched[i] = cloneFinding(finding)
		enriched[i].Affected = affectedDetails(finding, exposures, sc, idx, nsLabels)
		if exposure, ok := bestExposure(finding.AffectedResources, exposures); ok {
			enriched[i].Exposure = &exposure
		}
		pain, rem := worstAsset(enriched[i].Affected)
		enriched[i].Pain = pain
		enriched[i].Remediation = rem
	}
	return enriched
}

func suppressedWithWouldHaveBeen(findings []model.Finding, exposures map[model.ResourceRef]model.Exposure, sc *scoring.Config, idx, nsLabels map[string]map[string]string) []model.Finding {
	enriched := make([]model.Finding, len(findings))
	for i, finding := range findings {
		enriched[i] = cloneFinding(finding)
		enriched[i].Affected = affectedDetails(finding, exposures, sc, idx, nsLabels)
		if exposure, ok := bestExposure(finding.AffectedResources, exposures); ok {
			enriched[i].Exposure = &exposure
		}
		pain, rem := worstAsset(enriched[i].Affected)
		enriched[i].WouldHaveBeenPain = pain
		enriched[i].WouldHaveBeenRemediation = rem
		enriched[i].Pain = nil
		enriched[i].Remediation = nil
		for j := range enriched[i].Affected {
			enriched[i].Affected[j].Pain = nil
			enriched[i].Affected[j].Remediation = nil
		}
	}
	return enriched
}

func affectedDetails(finding model.Finding, exposures map[model.ResourceRef]model.Exposure, sc *scoring.Config, idx, nsLabels map[string]map[string]string) []model.Affected {
	details := make([]model.Affected, 0, len(finding.AffectedResources))
	for _, ref := range finding.AffectedResources {
		detail := model.Affected{Resource: ref}
		if exposure, ok := exposures[ref]; ok {
			value := exposure
			detail.Exposure = &value
		}
		detail.Pain, detail.Remediation = scoreAsset(sc, idx, nsLabels, ref, finding, internetReachable(detail.Exposure))
		details = append(details, detail)
	}
	return details
}

// worstAsset returns the PAIN and remediation of the most urgent affected
// resource: the one with the shortest FedRAMP deadline (a missing deadline ranks
// last), breaking ties by highest PAIN rank. Pain and remediation are taken from
// the same affected entry so they stay consistent.
func worstAsset(affected []model.Affected) (*model.Pain, *model.Remediation) {
	worst := -1
	for i := range affected {
		if affected[i].Pain == nil {
			continue
		}
		if worst < 0 || moreUrgent(affected[i], affected[worst]) {
			worst = i
		}
	}
	if worst < 0 {
		return nil, nil
	}
	var pain *model.Pain
	if affected[worst].Pain != nil {
		p := *affected[worst].Pain
		pain = &p
	}
	var rem *model.Remediation
	if affected[worst].Remediation != nil {
		r := *affected[worst].Remediation
		rem = &r
	}
	return pain, rem
}

func moreUrgent(a, b model.Affected) bool {
	da, db := deadlineKey(a.Remediation), deadlineKey(b.Remediation)
	if da != db {
		return da < db
	}
	return painRank(a.Pain) > painRank(b.Pain)
}

// deadlineKey returns the remediation deadline in days, mapping "no deadline" to
// +Inf so it sorts as least urgent.
func deadlineKey(r *model.Remediation) float64 {
	if r == nil || r.DeadlineDays < 0 {
		return math.Inf(1)
	}
	return r.DeadlineDays
}

func painRank(p *model.Pain) int {
	if p == nil {
		return 0
	}
	return scoring.Rank(p.Tier)
}

func bestExposure(resources []model.ResourceRef, exposures map[model.ResourceRef]model.Exposure) (model.Exposure, bool) {
	var protected *model.Exposure
	for _, ref := range resources {
		exposure, ok := exposures[ref]
		if !ok {
			continue
		}
		if exposure.InternetAccessible {
			return exposure, true
		}
		if protected == nil && exposure.Protection != nil {
			value := exposure
			protected = &value
		}
	}
	if protected != nil {
		return *protected, true
	}
	return model.Exposure{}, false
}

func cloneFinding(finding model.Finding) model.Finding {
	clone := finding
	clone.References = append([]string(nil), finding.References...)
	clone.AffectedResources = append([]model.ResourceRef(nil), finding.AffectedResources...)
	clone.Affected = cloneAffected(finding.Affected)
	if finding.EPSS != nil {
		value := *finding.EPSS
		clone.EPSS = &value
	}
	if finding.Vulnrichment != nil {
		value := *finding.Vulnrichment
		clone.Vulnrichment = &value
	}
	if finding.Exposure != nil {
		value := *finding.Exposure
		clone.Exposure = &value
	}
	if finding.Pain != nil {
		value := *finding.Pain
		clone.Pain = &value
	}
	if finding.Remediation != nil {
		value := *finding.Remediation
		clone.Remediation = &value
	}
	if finding.Suppression != nil {
		value := *finding.Suppression
		clone.Suppression = &value
	}
	if finding.WouldHaveBeenPain != nil {
		value := *finding.WouldHaveBeenPain
		clone.WouldHaveBeenPain = &value
	}
	if finding.WouldHaveBeenRemediation != nil {
		value := *finding.WouldHaveBeenRemediation
		clone.WouldHaveBeenRemediation = &value
	}
	return clone
}

func cloneAffected(affected []model.Affected) []model.Affected {
	if len(affected) == 0 {
		return nil
	}
	clone := make([]model.Affected, len(affected))
	for i, item := range affected {
		clone[i] = item
		if item.Exposure != nil {
			value := *item.Exposure
			clone[i].Exposure = &value
		}
		if item.Pain != nil {
			value := *item.Pain
			clone[i].Pain = &value
		}
		if item.Remediation != nil {
			value := *item.Remediation
			clone[i].Remediation = &value
		}
	}
	return clone
}

func severityAtLeast(got, min string) bool {
	if min == "" {
		return true
	}
	return severityRank(got) >= severityRank(min)
}

func severityRank(value string) int {
	switch strings.ToUpper(value) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "UNKNOWN":
		return 1
	default:
		return 0
	}
}

func formatEPSS(epss *model.EPSS) string {
	if epss == nil {
		return ""
	}
	return fmt.Sprintf("%.3f", epss.Score)
}

// worstPainTier returns the highest PAIN tier among a resource's findings.
func worstPainTier(findings []model.Finding) string {
	best := ""
	bestRank := 0
	for _, f := range findings {
		if f.Pain == nil {
			continue
		}
		if r := scoring.Rank(f.Pain.Tier); r > bestRank {
			bestRank, best = r, f.Pain.Tier
		}
	}
	return best
}

// soonestRemediation returns the shortest FedRAMP deadline among a resource's
// findings (findings with no deadline are ignored).
func soonestRemediation(findings []model.Finding) string {
	best := ""
	bestDays := math.Inf(1)
	for _, f := range findings {
		if f.Remediation == nil || f.Remediation.DeadlineDays < 0 {
			continue
		}
		if f.Remediation.DeadlineDays < bestDays {
			bestDays, best = f.Remediation.DeadlineDays, f.Remediation.Deadline
		}
	}
	return best
}

func formatPain(pain *model.Pain) string {
	if pain == nil {
		return ""
	}
	return pain.Tier
}

func formatRemediation(rem *model.Remediation) string {
	if rem == nil || rem.DeadlineDays < 0 {
		return ""
	}
	return rem.Deadline
}

func suppressionStatus(s *model.Suppression) string {
	if s == nil {
		return ""
	}
	return s.Status
}

func suppressionJustification(s *model.Suppression) string {
	if s == nil {
		return ""
	}
	if s.Justification != "" {
		return s.Justification
	}
	return s.ImpactStatement
}

func vulnrichmentValue(v *model.Vulnrichment, field string) string {
	if v == nil {
		return ""
	}
	switch field {
	case "automatable":
		return v.Automatable
	case "exploitation":
		return v.Exploitation
	case "technicalImpact":
		return v.TechnicalImpact
	default:
		return ""
	}
}

func formatAffectedResources(refs []model.ResourceRef) string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		values = append(values, resourceLabel(ref))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func formatResourceImages(images []model.ContainerImage) string {
	values := make([]string, 0, len(images))
	for _, image := range images {
		values = append(values, image.ImageRef)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func formatExposure(exposure *model.Exposure) string {
	if exposure == nil {
		return "unknown"
	}
	if exposure.InternetAccessible {
		return "yes"
	}
	if exposure.Protection != nil && exposure.Protection.Enabled {
		return "protected"
	}
	if exposure.RouteKind == "Service/NodePort" {
		return "nodeport"
	}
	return "no"
}

func resourceLabel(ref model.ResourceRef) string {
	parts := []string{ref.Kind, ref.Namespace, ref.Name}
	if ref.ContainerName != "" {
		parts = append(parts, ref.ContainerName)
	}
	return strings.Join(parts, "/")
}

func resourceSortKey(ref model.ResourceRef) string {
	return strings.Join([]string{ref.Namespace, ref.Kind, ref.Name, ref.ContainerType, ref.ContainerName}, "\x00")
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	copied := make(map[string]string, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}
