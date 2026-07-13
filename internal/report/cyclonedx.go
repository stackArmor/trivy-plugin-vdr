package report

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

// CycloneDX 1.6 VEX profile for FedRAMP Rev5 VDR/VER.
//
// This emits a CycloneDX 1.6 BOM whose vulnerabilities carry the CycloneDX
// analysis (state/justification/response/detail) disposition vocabulary and a
// vdr:* property scheme, per "A CycloneDX VEX Profile for FedRAMP Rev5 VDR/VER
// Disposition and Response". FedRAMP disposition is per-(vulnerability, asset)
// while a CycloneDX analysis is per-vulnerability, so we emit one vulnerability
// entry per (CVE, affected asset) pair. Each entry's affects[] references the
// affected asset's component bom-ref, keeping per-asset PAIN and reachability
// lossless.
//
// The document is deterministic: the same model.Report renders the same bytes
// (no wall-clock or random values are introduced here; the metadata timestamp
// is taken verbatim from the report's GeneratedAt).

const (
	cdxBOMFormat   = "CycloneDX"
	cdxSpecVersion = "1.6"
	cdxToolName    = "trivy-plugin-vdr"
	cdxToolVendor  = "stackArmor"
)

type cdxDocument struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Version         int                `json:"version"`
	Metadata        *cdxMetadata       `json:"metadata,omitempty"`
	Components      []cdxComponent     `json:"components,omitempty"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp,omitempty"`
	Tools     *cdxTools     `json:"tools,omitempty"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components,omitempty"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Publisher  string        `json:"publisher,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxVulnerability struct {
	BOMRef     string        `json:"bom-ref,omitempty"`
	ID         string        `json:"id"`
	Source     *cdxSource    `json:"source,omitempty"`
	Published  string        `json:"published,omitempty"`
	Updated    string        `json:"updated,omitempty"`
	Ratings    []cdxRating   `json:"ratings,omitempty"`
	CWEs       []int         `json:"cwes,omitempty"`
	Analysis   *cdxAnalysis  `json:"analysis,omitempty"`
	Affects    []cdxAffect   `json:"affects"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type cdxRating struct {
	Severity string     `json:"severity,omitempty"`
	Method   string     `json:"method,omitempty"`
	Vector   string     `json:"vector,omitempty"`
	Source   *cdxSource `json:"source,omitempty"`
}

type cdxAnalysis struct {
	State         string   `json:"state,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

// RenderCycloneDX writes the report as a CycloneDX 1.6 VEX document (indented
// JSON). It is added alongside the native JSON and table renderers; those are
// unchanged.
func RenderCycloneDX(w io.Writer, report model.Report) error {
	doc := ToCycloneDX(report)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(doc)
}

// ToCycloneDX converts a model.Report into a CycloneDX 1.6 VEX document. The
// report should be built with the resources view so that per-asset findings and
// WorkloadPosture are available; the converter also tolerates the findings view
// by falling back to each finding's Affected list.
func ToCycloneDX(report model.Report) cdxDocument {
	doc := cdxDocument{
		BOMFormat:   cdxBOMFormat,
		SpecVersion: cdxSpecVersion,
		Version:     1,
		Metadata: &cdxMetadata{
			Tools: &cdxTools{
				Components: []cdxComponent{{
					Type:      "application",
					Name:      cdxToolName,
					Publisher: cdxToolVendor,
				}},
			},
		},
	}
	if !report.GeneratedAt.IsZero() {
		doc.Metadata.Timestamp = report.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if report.ContextName != "" {
		doc.Metadata.Component = &cdxComponent{
			Type:   "application",
			BOMRef: "urn:vdr:report:" + report.ContextName,
			Name:   report.ContextName,
		}
	}

	components := map[string]*cdxComponent{}
	order := []string{}
	ensureComponent := func(ref model.ResourceRef, exposure *model.Exposure, posture *model.WorkloadPosture, image string) string {
		id := assetBOMRef(ref)
		if _, ok := components[id]; ok {
			return id
		}
		comp := buildAssetComponent(id, ref, exposure, posture, image)
		components[id] = &comp
		order = append(order, id)
		return id
	}

	var vulns []cdxVulnerability

	// Active findings: the resources view carries one asset (container-scoped
	// ResourceReport) per component, each with its per-asset scored findings and
	// WorkloadPosture.
	for i := range report.Resources {
		res := report.Resources[i]
		img := firstImageRef(res.Images)
		ref := ensureComponent(res.Resource, res.Exposure, res.Posture, img)
		for j := range res.Findings {
			finding := res.Findings[j]
			vulns = append(vulns, vulnerabilityFor(finding, ref, res.Exposure))
		}
	}

	// Findings view fallback: no report.Resources, so derive assets from each
	// finding's Affected list.
	if len(report.Resources) == 0 {
		for i := range report.Findings {
			finding := report.Findings[i]
			for _, aff := range affectedForFinding(finding) {
				ref := ensureComponent(aff.Resource, aff.Exposure, nil, finding.ImageRef)
				scoped := finding
				scoped.Pain = aff.Pain
				scoped.Remediation = aff.Remediation
				vulns = append(vulns, vulnerabilityFor(scoped, ref, aff.Exposure))
			}
		}
	}

	// Suppressed (dispositioned) findings are kept separately for audit; each is
	// emitted per affected asset with its VEX-derived analysis.
	for i := range report.SuppressedFindings {
		finding := report.SuppressedFindings[i]
		for _, aff := range affectedForFinding(finding) {
			ref := ensureComponent(aff.Resource, aff.Exposure, nil, finding.ImageRef)
			vulns = append(vulns, vulnerabilityFor(finding, ref, aff.Exposure))
		}
	}

	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	for _, id := range order {
		doc.Components = append(doc.Components, *components[id])
	}

	sort.SliceStable(vulns, func(i, j int) bool {
		if vulns[i].ID != vulns[j].ID {
			return vulns[i].ID < vulns[j].ID
		}
		ri, rj := affectRef(vulns[i]), affectRef(vulns[j])
		if ri != rj {
			return ri < rj
		}
		return vulns[i].BOMRef < vulns[j].BOMRef
	})
	doc.Vulnerabilities = vulns
	return doc
}

func affectRef(v cdxVulnerability) string {
	if len(v.Affects) == 0 {
		return ""
	}
	return v.Affects[0].Ref
}

// affectedForFinding returns the per-asset Affected entries for a finding. When a
// finding carries no Affected list it falls back to its AffectedResources.
func affectedForFinding(finding model.Finding) []model.Affected {
	if len(finding.Affected) > 0 {
		return finding.Affected
	}
	out := make([]model.Affected, 0, len(finding.AffectedResources))
	for _, ref := range finding.AffectedResources {
		out = append(out, model.Affected{Resource: ref})
	}
	return out
}

func firstImageRef(images []model.ContainerImage) string {
	if len(images) == 0 {
		return ""
	}
	return images[0].ImageRef
}

// assetBOMRef builds a stable, deterministic bom-ref for a container-scoped asset.
// It excludes containerType and restartPolicy so the same asset referenced from
// the inventory index and from a finding's AffectedResources resolves identically.
func assetBOMRef(ref model.ResourceRef) string {
	parts := []string{}
	for _, p := range []string{ref.Provider, ref.Project, ref.Region, ref.Namespace, ref.Kind, ref.Name, ref.ContainerName} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return "urn:vdr:asset:" + strings.Join(parts, "/")
}

func buildAssetComponent(id string, ref model.ResourceRef, exposure *model.Exposure, posture *model.WorkloadPosture, image string) cdxComponent {
	compType := "application"
	if ref.Kind == "Image" {
		compType = "container"
	}
	name := resourceLabel(ref)
	if ref.Kind == "Image" && ref.Name != "" {
		name = ref.Name
	}
	comp := cdxComponent{
		Type:   compType,
		BOMRef: id,
		Name:   name,
	}
	var props []cdxProperty
	add := func(name, value string) {
		if value == "" {
			return
		}
		props = append(props, cdxProperty{Name: name, Value: value})
	}
	if image != "" {
		add("vdr:imageRef", image)
	}
	if exposure != nil {
		add("vdr:assetInternetReachable", strconv.FormatBool(exposure.InternetAccessible))
		if route, ok := backendRoute(exposure); ok {
			add("vdr:exposedBackendProtocol", route.BackendProtocol)
			add("vdr:exposedBackendProtocolVersion", route.BackendProtocolVersion)
			add("vdr:exposedBackendAlpn", strings.Join(route.ALPN, ","))
		}
		add("vdr:routeEvidence", routeEvidence(exposure))
	}
	props = append(props, postureProperties(posture)...)
	comp.Properties = props
	return comp
}

// backendRoute returns the first route that records a backend protocol, so the
// exposed-surface properties describe the concrete backend the internet reaches.
func backendRoute(exposure *model.Exposure) (model.RouteMetadata, bool) {
	if exposure == nil {
		return model.RouteMetadata{}, false
	}
	for _, route := range exposure.Routes {
		if route.BackendProtocol != "" || route.BackendProtocolVersion != "" || len(route.ALPN) > 0 {
			return route, true
		}
	}
	return model.RouteMetadata{}, false
}

func routeEvidence(exposure *model.Exposure) string {
	if exposure == nil {
		return ""
	}
	if len(exposure.Evidence) > 0 {
		return strings.Join(exposure.Evidence, "; ")
	}
	if exposure.RouteKind != "" || exposure.RouteName != "" {
		return strings.TrimSpace(exposure.RouteKind + " " + exposure.RouteName)
	}
	return ""
}

// postureProperties flattens the neutral WorkloadPosture facts into vdr:posture:*
// properties, in a fixed order. Boolean facts are emitted only when true (mirroring
// the model's omitempty semantics); pointer/slice/string facts are emitted when set.
func postureProperties(posture *model.WorkloadPosture) []cdxProperty {
	if posture == nil {
		return nil
	}
	var props []cdxProperty
	addBool := func(name string, v bool) {
		if v {
			props = append(props, cdxProperty{Name: name, Value: "true"})
		}
	}
	addStr := func(name, v string) {
		if v != "" {
			props = append(props, cdxProperty{Name: name, Value: v})
		}
	}
	addList := func(name string, v []string) {
		if len(v) > 0 {
			props = append(props, cdxProperty{Name: name, Value: strings.Join(v, ",")})
		}
	}
	if sc := posture.SecurityContext; sc != nil {
		addBool("vdr:posture:securityContext:readOnlyRootFilesystem", sc.ReadOnlyRootFilesystem)
		addBool("vdr:posture:securityContext:runAsNonRoot", sc.RunAsNonRoot)
		addBool("vdr:posture:securityContext:privileged", sc.Privileged)
		addBool("vdr:posture:securityContext:allowPrivilegeEscalation", sc.AllowPrivilegeEscalation)
		addList("vdr:posture:securityContext:droppedCapabilities", sc.DroppedCapabilities)
		addStr("vdr:posture:securityContext:seccompProfileType", sc.SeccompProfileType)
	}
	if wl := posture.Workload; wl != nil {
		if wl.Replicas != nil {
			addStr("vdr:posture:workload:replicas", strconv.FormatInt(int64(*wl.Replicas), 10))
		}
		addBool("vdr:posture:workload:hasPodDisruptionBudget", wl.HasPodDisruptionBudget)
		addBool("vdr:posture:workload:zoneSpread", wl.ZoneSpread)
		addBool("vdr:posture:workload:livenessProbe", wl.LivenessProbe)
		addBool("vdr:posture:workload:readinessProbe", wl.ReadinessProbe)
	}
	if id := posture.Identity; id != nil {
		addStr("vdr:posture:identity:serviceAccountName", id.ServiceAccountName)
		if id.AutomountServiceAccountToken != nil {
			addStr("vdr:posture:identity:automountServiceAccountToken", strconv.FormatBool(*id.AutomountServiceAccountToken))
		}
		addBool("vdr:posture:identity:envFromSecretRef", id.EnvFromSecretRef)
	}
	if vol := posture.Volumes; vol != nil {
		addList("vdr:posture:volumes:writableVolumeMounts", vol.WritableVolumeMounts)
	}
	if np := posture.NetworkPolicy; np != nil {
		addBool("vdr:posture:networkPolicy:selectedByEgressPolicy", np.SelectedByEgressPolicy)
		addBool("vdr:posture:networkPolicy:egressDefaultDeny", np.EgressDefaultDeny)
		addList("vdr:posture:networkPolicy:egressAllowedCidrs", np.EgressAllowedCIDRs)
		addList("vdr:posture:networkPolicy:egressDeniedByExcept", np.EgressDeniedByExcept)
		addBool("vdr:posture:networkPolicy:selectedByIngressPolicy", np.SelectedByIngressPolicy)
	}
	return props
}

func vulnerabilityFor(finding model.Finding, assetRef string, exposure *model.Exposure) cdxVulnerability {
	pain, rem := dispositionScore(finding)
	vuln := cdxVulnerability{
		ID:      finding.ID,
		BOMRef:  vulnBOMRef(finding, assetRef),
		Affects: []cdxAffect{{Ref: assetRef}},
	}
	if src := vulnSource(finding); src != nil {
		vuln.Source = src
	}
	if rating := vulnRating(finding); rating != nil {
		vuln.Ratings = []cdxRating{*rating}
	}
	if finding.PublishedDate != nil {
		vuln.Published = finding.PublishedDate.UTC().Format(time.RFC3339)
	}
	if finding.LastModifiedDate != nil {
		vuln.Updated = finding.LastModifiedDate.UTC().Format(time.RFC3339)
	}
	vuln.CWEs = numericCWEs(finding.CWEs)
	vuln.Analysis = analysisFor(finding)

	var props []cdxProperty
	add := func(name, value string) {
		if value == "" {
			return
		}
		props = append(props, cdxProperty{Name: name, Value: value})
	}
	if pain != nil {
		add("vdr:pain", pain.Tier)
		add("vdr:painWord", pain.Word)
		add("vdr:archetype", pain.Archetype)
	}
	add("vdr:cwes", strings.Join(finding.CWEs, ","))
	if rem != nil {
		add("vdr:remediationTrack", rem.Column)
		add("vdr:findingInternetReachable", strconv.FormatBool(rem.IRV))
	}
	add("vdr:reachabilityDecision", reachabilityDecision(rem, exposure))
	add("vdr:target", finding.Target)
	add("vdr:targetClass", finding.TargetClass)
	add("vdr:targetType", finding.TargetType)
	add("vdr:packageId", finding.PackageID)
	if finding.PackageName != "" {
		add("vdr:affectedPackage", finding.PackageName)
	}
	add("vdr:affectedPackagePurl", finding.PackagePURL)
	add("vdr:affectedPackageUid", finding.PackageUID)
	add("vdr:affectedPackagePath", finding.PackagePath)
	add("vdr:affectedPackageRelationship", finding.PackageRelationship)
	add("vdr:severitySource", finding.SeveritySource)
	add("vdr:vendorSeverity", formatStringMap(finding.VendorSeverity))
	if finding.DataSource != nil {
		add("vdr:dataSourceId", finding.DataSource.ID)
		add("vdr:dataSourceName", finding.DataSource.Name)
		add("vdr:dataSourceUrl", finding.DataSource.URL)
		add("vdr:dataSourceBaseId", finding.DataSource.BaseID)
	}
	add("vdr:primaryUrl", finding.PrimaryURL)
	add("vdr:scannerFingerprint", finding.ScannerFingerprint)
	add("vdr:vendorIds", strings.Join(finding.VendorIDs, ","))
	vuln.Properties = props
	return vuln
}

// dispositionScore returns the PAIN and remediation to surface for a finding. For
// a suppressed finding the active values are cleared, so its would-have-been
// values (the score that applied before disposition) are used instead.
func dispositionScore(finding model.Finding) (*model.Pain, *model.Remediation) {
	if finding.Suppressed {
		return finding.WouldHaveBeenPain, finding.WouldHaveBeenRemediation
	}
	return finding.Pain, finding.Remediation
}

func vulnBOMRef(finding model.Finding, assetRef string) string {
	parts := []string{"urn:vdr:vuln", finding.ID, assetRef}
	if finding.PackageName != "" {
		parts = append(parts, finding.PackageName)
	}
	return strings.Join(parts, "|")
}

func vulnSource(finding model.Finding) *cdxSource {
	if finding.DataSource != nil {
		name := finding.DataSource.Name
		if name == "" {
			name = finding.DataSource.ID
		}
		if name != "" || finding.DataSource.URL != "" {
			return &cdxSource{Name: name, URL: finding.DataSource.URL}
		}
	}
	if strings.HasPrefix(finding.ID, "CVE-") {
		return &cdxSource{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + finding.ID}
	}
	if strings.HasPrefix(finding.ID, "GHSA-") {
		return &cdxSource{Name: "GitHub Advisory Database", URL: "https://github.com/advisories/" + finding.ID}
	}
	return nil
}

func vulnRating(finding model.Finding) *cdxRating {
	severity := cdxSeverity(finding.Severity)
	vector := finding.CVSSVector
	if severity == "" && vector == "" {
		return nil
	}
	rating := &cdxRating{Severity: severity, Vector: vector}
	if finding.SeveritySource != "" {
		rating.Source = &cdxSource{Name: finding.SeveritySource}
	}
	if vector != "" {
		rating.Method = cvssMethod(vector)
	}
	return rating
}

func formatStringMap(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, ",")
}

func cdxSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "NONE":
		return "none"
	case "UNKNOWN":
		return "unknown"
	default:
		return ""
	}
}

func cvssMethod(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0"):
		return "CVSSv4"
	case strings.HasPrefix(vector, "CVSS:3.1"):
		return "CVSSv31"
	case strings.HasPrefix(vector, "CVSS:3.0"):
		return "CVSSv3"
	case strings.HasPrefix(vector, "CVSS:2"):
		return "CVSSv2"
	default:
		return "other"
	}
}

// numericCWEs parses "CWE-<n>" identifiers into the numeric ids CycloneDX's cwes
// array expects, sorted ascending and de-duplicated.
func numericCWEs(cwes []string) []int {
	seen := map[int]struct{}{}
	var out []int
	for _, cwe := range cwes {
		digits := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(cwe)), "CWE-")
		n, err := strconv.Atoi(digits)
		if err != nil {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// analysisFor maps a finding onto a CycloneDX analysis block per the FedRAMP VER
// profile. Active (undispositioned) findings default to state "exploitable"
// (VER-EVA-AIA: assume exploitable absent evidence). Suppressed findings map from
// their VEX status, with the free-text statement carried in detail and, when it
// matches a CycloneDX justification token, surfaced as analysis.justification.
func analysisFor(finding model.Finding) *cdxAnalysis {
	if !finding.Suppressed {
		return &cdxAnalysis{State: "exploitable"}
	}
	analysis := &cdxAnalysis{State: cdxState(suppressionStatusValue(finding.Suppression))}
	if finding.Suppression != nil {
		statement := finding.Suppression.Justification
		if j := cdxJustification(statement); j != "" {
			analysis.Justification = j
		}
		detail := finding.Suppression.ImpactStatement
		if detail == "" && analysis.Justification == "" {
			detail = statement
		}
		analysis.Detail = detail
	}
	return analysis
}

func suppressionStatusValue(s *model.Suppression) string {
	if s == nil {
		return ""
	}
	return s.Status
}

// cdxState maps a VEX status (as recorded on a suppression) onto a CycloneDX
// analysis.state. Unknown values map to the non-committal "in_triage".
func cdxState(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "not_affected", "notaffected":
		return "not_affected"
	case "false_positive", "falsepositive":
		return "false_positive"
	case "affected", "exploitable":
		return "exploitable"
	case "fixed", "resolved":
		return "resolved"
	case "under_investigation", "under_evaluation", "in_triage":
		return "in_triage"
	default:
		return "in_triage"
	}
}

// cdxJustification returns the CycloneDX justification token when the given text
// exactly names one; otherwise it returns "" and the text is carried in detail.
func cdxJustification(text string) string {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "code_not_present":
		return "code_not_present"
	case "code_not_reachable":
		return "code_not_reachable"
	case "requires_configuration":
		return "requires_configuration"
	case "requires_dependency":
		return "requires_dependency"
	case "requires_environment":
		return "requires_environment"
	case "protected_by_compiler":
		return "protected_by_compiler"
	case "protected_at_runtime":
		return "protected_at_runtime"
	case "protected_at_perimeter":
		return "protected_at_perimeter"
	case "protected_by_mitigating_control":
		return "protected_by_mitigating_control"
	default:
		return ""
	}
}

// reachabilityDecision records the per-finding internet-reachability determination
// using the profile's vocabulary. When the asset is not internet-reachable every
// finding on it is NIRV; when it is reachable an internet-reachable finding remains
// IRV by default (insufficient evidence to downgrade the required surface).
func reachabilityDecision(rem *model.Remediation, exposure *model.Exposure) string {
	assetReachable := exposure != nil && exposure.InternetAccessible
	if !assetReachable {
		return "not_internet_reachable"
	}
	if rem != nil && rem.IRV {
		return "insufficient_evidence_to_downgrade"
	}
	if rem != nil {
		return "downgraded_not_reachable"
	}
	return ""
}
