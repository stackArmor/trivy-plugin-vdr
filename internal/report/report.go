package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
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
}

func Build(inventory *model.Inventory, findings []model.Finding, exposures map[model.ResourceRef]model.Exposure, options Options) model.Report {
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = time.Now().UTC()
	}
	if options.View == "" {
		options.View = ViewFindings
	}

	filtered := filterFindings(findings, options.MinSeverity, options.MinEPSS)
	resourceReports := buildResourceReports(inventory, filtered, exposures)
	report := model.Report{
		GeneratedAt: options.GeneratedAt,
		Summary:     buildSummary(inventory, filtered, resourceReports),
		Warnings:    append([]string(nil), options.Warnings...),
	}
	if options.View == ViewResources {
		report.Resources = resourceReports
		return report
	}

	report.Findings = findingsWithBestExposure(filtered, exposures)
	return report
}

func RenderJSON(w io.Writer, report model.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func RenderTable(w io.Writer, report model.Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(report.Resources) > 0 {
		if _, err := fmt.Fprintln(tw, "NAMESPACE\tRESOURCE\tCONTAINER\tIMAGE\tEXPOSED\tFINDINGS"); err != nil {
			return err
		}
		for _, resource := range report.Resources {
			if _, err := fmt.Fprintf(tw, "%s\t%s/%s\t%s\t%s\t%s\t%d\n",
				resource.Resource.Namespace,
				resource.Resource.Kind,
				resource.Resource.Name,
				resource.Resource.ContainerName,
				formatResourceImages(resource.Images),
				formatExposure(resource.Exposure),
				len(resource.Findings),
			); err != nil {
				return err
			}
		}
		return tw.Flush()
	}
	if _, err := fmt.Fprintln(tw, "ID\tSEVERITY\tEPSS\tAUTOMATABLE\tEXPLOITATION\tTECHNICAL IMPACT\tIMAGE\tAFFECTED"); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			finding.ID,
			finding.Severity,
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
	return tw.Flush()
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

func buildResourceReports(inventory *model.Inventory, findings []model.Finding, exposures map[model.ResourceRef]model.Exposure) []model.ResourceReport {
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

func findingsWithBestExposure(findings []model.Finding, exposures map[model.ResourceRef]model.Exposure) []model.Finding {
	enriched := make([]model.Finding, len(findings))
	for i, finding := range findings {
		enriched[i] = cloneFinding(finding)
		enriched[i].Affected = affectedDetails(finding.AffectedResources, exposures)
		if exposure, ok := bestExposure(finding.AffectedResources, exposures); ok {
			enriched[i].Exposure = &exposure
		}
	}
	return enriched
}

func affectedDetails(resources []model.ResourceRef, exposures map[model.ResourceRef]model.Exposure) []model.Affected {
	details := make([]model.Affected, 0, len(resources))
	for _, ref := range resources {
		detail := model.Affected{Resource: ref}
		if exposure, ok := exposures[ref]; ok {
			value := exposure
			detail.Exposure = &value
		}
		details = append(details, detail)
	}
	return details
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
