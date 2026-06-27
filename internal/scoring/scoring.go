// Package scoring computes the FedRAMP Rev5 VDR Potential Agency Impact rating
// (PAIN, N1-N5) and the remediation deadline for a vulnerability finding on a
// given asset.
//
// PAIN = f(SEVERITY, SCOPE), where SEVERITY is the CVSS impact vector (C/I/A)
// re-weighted by the asset's CR/IR/AR requirements (driven by its archetype),
// and SCOPE is whether the asset serves one agency or more than one.
//
// The remediation deadline is the FedRAMP VDR-TFR-PVR matrix entry selected by
// the provider Certification Class, the PAIN rating, and the exploitability
// column: LEV+IRV, LEV+NIRV, or NLEV. LEV (likely exploitable) is EPSS >=
// threshold OR active exploitation; IRV is internet reachability.
//
// The built-in Default() rubric is self-contained; an optional YAML or JSON
// config file may be layered on top (deep-merged) to add tenant-specific rules
// (namespace/name archetype assignment for workloads that cannot carry labels)
// or to tune the catalog, EPSS threshold, or default Class.
package scoring

import (
	"fmt"
	"math"
	"os"
	"path"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Archetype maps an asset class to its CVSS environmental requirements and
// whether it is a "scope amplifier" (shared infrastructure whose compromise
// crosses tenant boundaries).
type Archetype struct {
	Lens      string `json:"lens" yaml:"lens"`
	CR        string `json:"cr" yaml:"cr"`
	IR        string `json:"ir" yaml:"ir"`
	AR        string `json:"ar" yaml:"ar"`
	Amplifier bool   `json:"amplifier" yaml:"amplifier"`
}

// NamespaceRule assigns an archetype to all workloads in namespaces matching a
// glob (e.g. "kube-system", "gke-managed-*"). Used for workloads that cannot
// carry in-cluster labels (managed, shared-responsibility components).
type NamespaceRule struct {
	Match     string `json:"match" yaml:"match"`
	Archetype string `json:"archetype" yaml:"archetype"`
}

// NameRule assigns an archetype to workloads whose name matches a glob, optionally
// scoped to a namespace glob. Evaluated before namespace rules.
type NameRule struct {
	Namespace string `json:"namespace" yaml:"namespace"`
	Match     string `json:"match" yaml:"match"`
	Archetype string `json:"archetype" yaml:"archetype"`
}

// LabelKeys are the label keys read from a workload (or its namespace) to resolve
// its archetype, multi-agency scope, and Certification Class.
type LabelKeys struct {
	Archetype   string `json:"archetype" yaml:"archetype"`
	MultiAgency string `json:"multiAgency" yaml:"multiAgency"`
	Class       string `json:"class" yaml:"class"`
}

// Defaults hold the cluster-wide fallbacks applied when a workload (or its
// namespace) carries no explicit signal. Class and MultiAgency here are the
// cluster-wide defaults; main may populate them from a cluster ConfigMap.
type Defaults struct {
	MultiAgency bool   `json:"multiAgency" yaml:"multiAgency"`
	Archetype   string `json:"archetype" yaml:"archetype"`
	Class       string `json:"class" yaml:"class"`
}

// Config is the full scoring rubric.
type Config struct {
	Archetypes     map[string]Archetype `json:"archetypes" yaml:"archetypes"`
	LabelKeys      LabelKeys            `json:"labelKeys" yaml:"labelKeys"`
	Defaults       Defaults             `json:"defaults" yaml:"defaults"`
	NamespaceRules []NamespaceRule      `json:"namespaceRules" yaml:"namespaceRules"`
	NameRules      []NameRule           `json:"nameRules" yaml:"nameRules"`
	// MultiAgencyNamespaces are namespace globs whose workloads are treated as
	// multi-agency unless a more specific label says otherwise.
	MultiAgencyNamespaces []string `json:"multiAgencyNamespaces" yaml:"multiAgencyNamespaces"`
	// LEVEPSSThreshold is the EPSS score at or above which a finding is considered
	// Likely Exploitable (LEV). FedRAMP leaves the framework to the provider.
	LEVEPSSThreshold float64 `json:"levEpssThreshold" yaml:"levEpssThreshold"`
	// CSOServesMultipleAgencies enables the scope-amplifier effect: when true,
	// amplifier archetypes are treated as multi-agency regardless of their tag.
	// Single-tenant offerings leave this false.
	CSOServesMultipleAgencies bool `json:"csoServesMultipleAgencies" yaml:"csoServesMultipleAgencies"`
}

// Input describes one finding-on-asset to be scored.
type Input struct {
	CVSSVector      string
	Severity        string
	Namespace       string
	WorkloadName    string
	Labels          map[string]string // workload labels
	NamespaceLabels map[string]string // labels on the namespace object

	// TechnicalImpact is the CISA Vulnrichment SSVC technical impact (total|partial).
	// It acts as a floor on the CVSS impact shape: "total" raises each in-scope
	// CVSS dimension (one the vector marks Low/High, not None) to High before
	// CR/IR/AR weighting; "partial" or absent leaves the vector unchanged. It never
	// invents impact on a dimension the CVE does not touch.
	TechnicalImpact string

	// Exploitability / reachability inputs for the remediation column.
	EPSS              float64 // < 0 means unknown
	Exploitation      string  // CISA Vulnrichment exploitation: active|poc|none
	InternetReachable bool
}

// Result is the computed PAIN and remediation plus the inputs that produced them.
type Result struct {
	// PAIN
	Tier            string
	Word            string
	Severity        float64
	Archetype       string
	ArchetypeSource string
	SeveritySource  string // technicalImpact | cvss | severity
	CR              string
	IR              string
	AR              string
	MultiAgency     bool
	// Remediation (FedRAMP VDR-TFR-PVR)
	Class            string
	LEV              bool
	IRV              bool
	Column           string  // LEV+IRV | LEV+NIRV | NLEV
	DeadlineDays     float64 // < 0 means no FedRAMP deadline (PAIN-1)
	RemediationLabel string  // human-readable deadline (e.g. "12 hours", "32 days")
}

// Default returns the built-in rubric: the archetype catalog (13 named archetypes
// plus the H/H/H "unclassified" cluster-default for new/unclassified resources),
// standard label keys, an EPSS LEV threshold of 0.70, and a default Certification
// Class of B. It carries no namespace/name rules (those are tenant-specific) and
// assumes a single-tenant (single-agency) offering.
func Default() *Config {
	return &Config{
		Archetypes: map[string]Archetype{
			"cicd-pipeline":    {Lens: "control", CR: "H", IR: "H", AR: "H", Amplifier: true},
			"orchestrator":     {Lens: "control", CR: "H", IR: "H", AR: "H", Amplifier: true},
			"config-actuation": {Lens: "control", CR: "H", IR: "H", AR: "H", Amplifier: true},
			"identity-secrets": {Lens: "control", CR: "H", IR: "H", AR: "H", Amplifier: true},
			"security-tooling": {Lens: "control", CR: "H", IR: "H", AR: "M", Amplifier: false},
			"change-record":    {Lens: "control", CR: "M", IR: "M", AR: "M", Amplifier: false},
			"data-sensitive":   {Lens: "data", CR: "H", IR: "H", AR: "H", Amplifier: false},
			"data-backbone":    {Lens: "data", CR: "H", IR: "H", AR: "H", Amplifier: true},
			"app-tier":         {Lens: "data", CR: "M", IR: "M", AR: "H", Amplifier: false},
			"batch-analytics":  {Lens: "data", CR: "M", IR: "M", AR: "L", Amplifier: false},
			"public-edge":      {Lens: "data", CR: "L", IR: "L", AR: "H", Amplifier: false},
			"internal-tooling": {Lens: "data", CR: "L", IR: "L", AR: "L", Amplifier: false},
			"dev-test":         {Lens: "data", CR: "L", IR: "L", AR: "L", Amplifier: false},
			// unclassified is the built-in cluster-default archetype for new or
			// otherwise-unclassified resources: CR/IR/AR=High so they score loudly
			// (single-agency H/H/H lands at PAIN-4 on a high-impact CVE) and surface
			// for deliberate classification, without forcing the multi-agency N5
			// fail-safe. Not an amplifier.
			"unclassified": {Lens: "control", CR: "H", IR: "H", AR: "H", Amplifier: false},
		},
		LabelKeys: LabelKeys{
			Archetype:   "vdr.fedramp.io/asset-archetype",
			MultiAgency: "vdr.fedramp.io/multi-agency",
			Class:       "vdr.fedramp.io/class",
		},
		Defaults: Defaults{
			MultiAgency: false,
			Archetype:   "unclassified",
			Class:       "B",
		},
		LEVEPSSThreshold:          0.70,
		CSOServesMultipleAgencies: false,
	}
}

// Load reads a YAML or JSON scoring config from path and layers it over the
// built-in defaults: archetype map entries are merged (overrides/additions),
// rule lists are replaced, and present scalars override. Fields absent from the
// file keep their default values. (YAML is a superset of JSON, so one decoder
// handles both formats.)
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse scoring config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("scoring config %q: %w", path, err)
	}
	return cfg, nil
}

// ApplyClusterDefaults layers cluster-wide FedRAMP metadata from a ConfigMap's
// data over the current config. A full scoring document may be embedded under a
// "scoring.yaml"/"scoring" key (archetypes, rules, defaults) and is deep-merged
// exactly like a --scoring-config file; the scalar keys "class" and
// "multiAgency"/"multi-agency" are convenience overrides that win over anything
// the embedded document set. ConfigMap values take precedence over the config
// file's defaults.
func (c *Config) ApplyClusterDefaults(data map[string]string) error {
	if len(data) == 0 {
		return nil
	}
	for _, key := range []string{"scoring.yaml", "scoring", "config.yaml", "config"} {
		doc, ok := data[key]
		if !ok || strings.TrimSpace(doc) == "" {
			continue
		}
		if err := yaml.Unmarshal([]byte(doc), c); err != nil {
			return fmt.Errorf("parse cluster scoring config (%s): %w", key, err)
		}
		break
	}
	if v := normalizeClass(data["class"]); v != "" {
		c.Defaults.Class = v
	}
	ma, ok := data["multiAgency"]
	if !ok {
		ma = data["multi-agency"]
	}
	if b, ok := parseBoolLabel(ma); ok {
		c.Defaults.MultiAgency = b
	}
	return c.validate()
}

func (c *Config) validate() error {
	for i, r := range c.NamespaceRules {
		if _, ok := c.Archetypes[r.Archetype]; !ok {
			return fmt.Errorf("namespaceRules[%d] references unknown archetype %q", i, r.Archetype)
		}
	}
	for i, r := range c.NameRules {
		if _, ok := c.Archetypes[r.Archetype]; !ok {
			return fmt.Errorf("nameRules[%d] references unknown archetype %q", i, r.Archetype)
		}
	}
	if c.Defaults.Class != "" && normalizeClass(c.Defaults.Class) == "" {
		return fmt.Errorf("defaults.class %q must be one of A, B, C, D", c.Defaults.Class)
	}
	if c.Defaults.Archetype != "" {
		if _, ok := c.Archetypes[c.Defaults.Archetype]; !ok {
			return fmt.Errorf("defaults.archetype %q is not a known archetype", c.Defaults.Archetype)
		}
	}
	return nil
}

// Score computes the PAIN and FedRAMP remediation deadline for a finding-on-asset.
func (c *Config) Score(in Input) Result {
	arch, source, found := c.resolveArchetype(in.Namespace, in.WorkloadName, in.Labels, in.NamespaceLabels)

	var a Archetype
	forceMulti := false
	if found {
		a = c.Archetypes[arch]
	} else {
		// Fail-safe: an unclassified asset is treated as CR/IR/AR=High and
		// multi-agency=true, which floors the finding toward N5. Missing metadata
		// never lowers PAIN; it surfaces the asset for classification.
		a = Archetype{Lens: "control", CR: "H", IR: "H", AR: "H", Amplifier: true}
		arch = c.Defaults.Archetype
		forceMulti = true
	}

	cImp, iImp, aImp, sevSource := impact(in.TechnicalImpact, in.CVSSVector, in.Severity)
	cr, ir, ar := weight(a.CR), weight(a.IR), weight(a.AR)
	isc := 1 - ((1 - cImp*cr) * (1 - iImp*ir) * (1 - aImp*ar))
	s := math.Min(isc, 0.915) / 0.915
	word := wordFromScalar(s)

	multi := c.resolveMultiAgency(in.Namespace, in.Labels, in.NamespaceLabels)
	effectiveMulti := multi || forceMulti || (a.Amplifier && c.CSOServesMultipleAgencies)
	tier := tierFromWord(word, effectiveMulti)

	// Remediation: FedRAMP VDR-TFR-PVR matrix[Class][PAIN][column].
	class := c.resolveClass(in.Labels, in.NamespaceLabels)
	lev := c.isLEV(in)
	irv := in.InternetReachable
	column := remediationColumn(lev, irv)
	days, label := remediationDeadline(class, tier, column)

	return Result{
		Tier:             tier,
		Word:             word,
		Severity:         s,
		Archetype:        arch,
		ArchetypeSource:  source,
		SeveritySource:   sevSource,
		CR:               normalizeReq(a.CR),
		IR:               normalizeReq(a.IR),
		AR:               normalizeReq(a.AR),
		MultiAgency:      effectiveMulti,
		Class:            class,
		LEV:              lev,
		IRV:              irv,
		Column:           column,
		DeadlineDays:     days,
		RemediationLabel: label,
	}
}

// resolveArchetype applies the precedence: workload label > namespace label >
// name rule > namespace rule > fail-safe. The returned bool is false only for the
// fail-safe path (no usable signal).
func (c *Config) resolveArchetype(namespace, name string, labels, nsLabels map[string]string) (string, string, bool) {
	if v, ok := labels[c.LabelKeys.Archetype]; ok {
		v = strings.TrimSpace(v)
		if _, known := c.Archetypes[v]; known {
			return v, "label", true
		}
		return "", "label-unknown", false
	}
	if v, ok := nsLabels[c.LabelKeys.Archetype]; ok {
		v = strings.TrimSpace(v)
		if _, known := c.Archetypes[v]; known {
			return v, "namespaceLabel", true
		}
		return "", "label-unknown", false
	}
	for _, r := range c.NameRules {
		if r.Namespace != "" {
			if ok, _ := path.Match(r.Namespace, namespace); !ok {
				continue
			}
		}
		if ok, _ := path.Match(r.Match, name); ok {
			if _, known := c.Archetypes[r.Archetype]; known {
				return r.Archetype, "nameRule", true
			}
		}
	}
	for _, r := range c.NamespaceRules {
		if ok, _ := path.Match(r.Match, namespace); ok {
			if _, known := c.Archetypes[r.Archetype]; known {
				return r.Archetype, "namespaceRule", true
			}
		}
	}
	// Cluster-wide default archetype: a known catalog entry named by
	// Defaults.Archetype catches new/unclassified resources without forcing them to
	// the multi-agency N5 fail-safe. The built-in default is the H/H/H
	// "unclassified" archetype; the true fail-safe below only triggers if a config
	// clears Defaults.Archetype or points it at an unknown name.
	if c.Defaults.Archetype != "" {
		if _, known := c.Archetypes[c.Defaults.Archetype]; known {
			return c.Defaults.Archetype, "default", true
		}
	}
	return "", "failsafe", false
}

// resolveMultiAgency: workload label > namespace label > multiAgencyNamespaces
// match > cluster default.
func (c *Config) resolveMultiAgency(namespace string, labels, nsLabels map[string]string) bool {
	if b, ok := parseBoolLabel(labels[c.LabelKeys.MultiAgency]); ok {
		return b
	}
	if b, ok := parseBoolLabel(nsLabels[c.LabelKeys.MultiAgency]); ok {
		return b
	}
	for _, glob := range c.MultiAgencyNamespaces {
		if ok, _ := path.Match(glob, namespace); ok {
			return true
		}
	}
	return c.Defaults.MultiAgency
}

// resolveClass: workload label > namespace label > cluster default > "B".
func (c *Config) resolveClass(labels, nsLabels map[string]string) string {
	if v := normalizeClass(labels[c.LabelKeys.Class]); v != "" {
		return v
	}
	if v := normalizeClass(nsLabels[c.LabelKeys.Class]); v != "" {
		return v
	}
	if v := normalizeClass(c.Defaults.Class); v != "" {
		return v
	}
	return "B"
}

func (c *Config) isLEV(in Input) bool {
	if strings.EqualFold(strings.TrimSpace(in.Exploitation), "active") {
		return true
	}
	return in.EPSS >= 0 && in.EPSS >= c.LEVEPSSThreshold
}

func parseBoolLabel(v string) (bool, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return false, false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, false
	}
	return b, true
}

func normalizeClass(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "A":
		return "A"
	case "B":
		return "B"
	case "C":
		return "C"
	case "D":
		return "D"
	default:
		return ""
	}
}

func remediationColumn(lev, irv bool) string {
	if !lev {
		return "NLEV"
	}
	if irv {
		return "LEV+IRV"
	}
	return "LEV+NIRV"
}

// remediationMatrix holds VDR-TFR-PVR deadlines in days (0.5 = 12 hours) keyed by
// Class, PAIN tier number (2..5), and column. PAIN-1 has no FedRAMP deadline.
// Class A and B share one table.
var remediationMatrix = map[string]map[int]map[string]float64{
	"A": classABMatrix,
	"B": classABMatrix,
	"C": {
		5: {"LEV+IRV": 2, "LEV+NIRV": 4, "NLEV": 16},
		4: {"LEV+IRV": 4, "LEV+NIRV": 8, "NLEV": 64},
		3: {"LEV+IRV": 16, "LEV+NIRV": 32, "NLEV": 128},
		2: {"LEV+IRV": 48, "LEV+NIRV": 128, "NLEV": 192},
	},
	"D": {
		5: {"LEV+IRV": 0.5, "LEV+NIRV": 1, "NLEV": 8},
		4: {"LEV+IRV": 2, "LEV+NIRV": 8, "NLEV": 32},
		3: {"LEV+IRV": 8, "LEV+NIRV": 16, "NLEV": 64},
		2: {"LEV+IRV": 24, "LEV+NIRV": 96, "NLEV": 192},
	},
}

var classABMatrix = map[int]map[string]float64{
	5: {"LEV+IRV": 4, "LEV+NIRV": 8, "NLEV": 32},
	4: {"LEV+IRV": 8, "LEV+NIRV": 32, "NLEV": 64},
	3: {"LEV+IRV": 32, "LEV+NIRV": 64, "NLEV": 192},
	2: {"LEV+IRV": 96, "LEV+NIRV": 160, "NLEV": 192},
}

func remediationDeadline(class, tier, column string) (float64, string) {
	painNum := Rank(tier)
	table, ok := remediationMatrix[class]
	if !ok {
		table = classABMatrix
	}
	row, ok := table[painNum]
	if !ok {
		// PAIN-1 (or unknown) has no FedRAMP remediation deadline.
		return -1, "no FedRAMP deadline"
	}
	days := row[column]
	return days, formatDeadline(days)
}

func formatDeadline(days float64) string {
	if days <= 0 {
		return "no FedRAMP deadline"
	}
	if days < 1 {
		hours := int(math.Round(days * 24))
		return fmt.Sprintf("%d hours", hours)
	}
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%g days", days)
}

// impact resolves the confidentiality/integrity/availability impact weights that
// feed PAIN severity, returning which source was used.
//
// The CVSS vector provides the *shape* — which of C/I/A the CVE touches (a None
// dimension means the CVE does not affect it). The SSVC technical impact then
// sets the *floor*: when "total", each in-scope dimension (one the vector marks
// Low or High, not None) is raised to High before CR/IR/AR weighting; "partial"
// or absent leaves the vector unchanged. Technical impact never invents impact on
// a dimension the CVE does not touch. When no usable vector is present, the
// qualitative severity supplies the shape and the same floor applies.
func impact(technicalImpact, vector, severity string) (cImp, iImp, aImp float64, source string) {
	cImp, iImp, aImp, source = baseImpact(vector, severity)
	if strings.EqualFold(strings.TrimSpace(technicalImpact), "total") {
		lifted := false
		if cImp > 0 && cImp < 0.56 {
			cImp, lifted = 0.56, true
		}
		if iImp > 0 && iImp < 0.56 {
			iImp, lifted = 0.56, true
		}
		if aImp > 0 && aImp < 0.56 {
			aImp, lifted = 0.56, true
		}
		if lifted {
			source += "+technicalImpact"
		}
	}
	return cImp, iImp, aImp, source
}

// baseImpact extracts the per-dimension CVSS impact weights (v3.x C/I/A or v4.0
// VC/VI/VA), falling back to the qualitative severity when no usable vector is
// present.
func baseImpact(vector, severity string) (cImp, iImp, aImp float64, source string) {
	if vector != "" {
		m := parseVector(vector)
		if strings.HasPrefix(strings.ToUpper(vector), "CVSS:4") {
			if _, ok := m["VC"]; ok {
				return impactWeight(m["VC"]), impactWeight(m["VI"]), impactWeight(m["VA"]), "cvss"
			}
		}
		if _, ok := m["C"]; ok {
			return impactWeight(m["C"]), impactWeight(m["I"]), impactWeight(m["A"]), "cvss"
		}
	}
	c, i, a := impactFromSeverity(severity)
	return c, i, a, "severity"
}

func parseVector(vector string) map[string]string {
	m := map[string]string{}
	for _, tok := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(tok, ":")
		if ok {
			m[strings.ToUpper(strings.TrimSpace(k))] = strings.ToUpper(strings.TrimSpace(v))
		}
	}
	return m
}

// impactWeight maps a CVSS impact metric value to its base weight. Handles v3/v4
// (N/L/H) and v2 (N/P/C).
func impactWeight(v string) float64 {
	switch strings.ToUpper(v) {
	case "H", "C":
		return 0.56
	case "L", "P":
		return 0.22
	case "N":
		return 0
	default:
		return 0
	}
}

func impactFromSeverity(severity string) (float64, float64, float64) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return 0.56, 0.56, 0.56
	case "MEDIUM":
		return 0.22, 0.22, 0.22
	case "LOW":
		return 0.22, 0, 0
	default:
		// Unknown/missing severity with no vector: conservative High.
		return 0.56, 0.56, 0.56
	}
}

// weight maps a CR/IR/AR requirement to its CVSS environmental weight.
func weight(req string) float64 {
	switch strings.ToUpper(strings.TrimSpace(req)) {
	case "H", "HIGH":
		return 1.5
	case "M", "MEDIUM":
		return 1.0
	case "L", "LOW":
		return 0.5
	default:
		return 1.0
	}
}

func normalizeReq(req string) string {
	switch strings.ToUpper(strings.TrimSpace(req)) {
	case "H", "HIGH":
		return "H"
	case "M", "MEDIUM":
		return "M"
	case "L", "LOW":
		return "L"
	default:
		return strings.ToUpper(strings.TrimSpace(req))
	}
}

func wordFromScalar(s float64) string {
	switch {
	case s < 0.25:
		return "Minimal"
	case s < 0.55:
		return "Narrow"
	case s < 0.80:
		return "Disruptive"
	default:
		return "Debilitating"
	}
}

func tierFromWord(word string, multi bool) string {
	switch word {
	case "Minimal":
		return "N1"
	case "Narrow":
		return "N2"
	case "Disruptive":
		if multi {
			return "N4"
		}
		return "N3"
	case "Debilitating":
		if multi {
			return "N5"
		}
		return "N4"
	default:
		return "N5"
	}
}

// Rank returns an orderable rank for a PAIN tier (N5 highest), so callers can
// pick the worst PAIN across multiple affected assets.
func Rank(tier string) int {
	switch strings.ToUpper(strings.TrimSpace(tier)) {
	case "N5":
		return 5
	case "N4":
		return 4
	case "N3":
		return 3
	case "N2":
		return 2
	case "N1":
		return 1
	default:
		return 0
	}
}
