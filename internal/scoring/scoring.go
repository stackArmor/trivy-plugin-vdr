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
// threshold, active exploitation, or the FRD-LEV floor (internet-reachable via
// direct exposure with a vector permitting low-complexity, unauthenticated
// automation: AV:N/AC:L/PR:N/UI:N); IRV is internet reachability.
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

	builtinpolicy "github.com/stackArmor/trivy-plugin-vdr/policy"
	"gopkg.in/yaml.v3"
)

// Archetype maps an asset class to its CVSS environmental requirements.
type Archetype struct {
	Lens string `json:"lens" yaml:"lens"`
	CR   string `json:"cr" yaml:"cr"`
	IR   string `json:"ir" yaml:"ir"`
	AR   string `json:"ar" yaml:"ar"`
}

// NamespaceRule assigns an archetype to all workloads in namespaces matching a
// glob (e.g. "kube-system", "gke-managed-*"). Used for workloads that cannot
// carry in-cluster labels (managed, shared-responsibility components).
type NamespaceRule struct {
	Match      string `json:"match" yaml:"match"`
	Archetype  string `json:"archetype" yaml:"archetype"`
	AssetValue string `json:"assetValue" yaml:"assetValue"`
}

// NameRule assigns an archetype to workloads whose name matches a glob, optionally
// scoped to a namespace glob. Evaluated before namespace rules.
type NameRule struct {
	Namespace  string `json:"namespace" yaml:"namespace"`
	Match      string `json:"match" yaml:"match"`
	Archetype  string `json:"archetype" yaml:"archetype"`
	AssetValue string `json:"assetValue" yaml:"assetValue"`
}

// KindRule assigns an archetype to workloads whose kind matches a glob (e.g.
// "Job", "Pod"), optionally scoped to namespace and name globs. Evaluated after
// name rules and before namespace rules, so a specific name rule or label can
// still override it. Typical use: standalone Jobs (Helm hooks, one-shot
// migrations) that carry no labels and whose generated names defeat name globs.
type KindRule struct {
	Kind       string `json:"kind" yaml:"kind"`
	Namespace  string `json:"namespace" yaml:"namespace"`
	Match      string `json:"match" yaml:"match"`
	Archetype  string `json:"archetype" yaml:"archetype"`
	AssetValue string `json:"assetValue" yaml:"assetValue"`
}

// LabelKeys are the label keys read from a workload (or its namespace) to resolve
// its archetype, multi-agency scope, and Certification Class.
type LabelKeys struct {
	Archetype   string `json:"archetype" yaml:"archetype"`
	AssetValue  string `json:"assetValue" yaml:"assetValue"`
	MultiAgency string `json:"multiAgency" yaml:"multiAgency"`
	Class       string `json:"class" yaml:"class"`
}

// Defaults hold the cluster-wide fallbacks applied when a workload (or its
// namespace) carries no explicit signal. Class and MultiAgency here are the
// cluster-wide defaults; main may populate them from a cluster ConfigMap.
type Defaults struct {
	MultiAgency bool   `json:"multiAgency" yaml:"multiAgency"`
	Archetype   string `json:"archetype" yaml:"archetype"`
	AssetValue  string `json:"assetValue" yaml:"assetValue"`
	Class       string `json:"class" yaml:"class"`
}

// WordThresholds are the (calibratable) cut points on the normalized
// environmental impact scalar S (0..1) that map it to a FedRAMP customer-effect
// word: S < Narrow => Minimal; < Disruptive => Narrow; < Debilitating =>
// Disruptive; else Debilitating. Must be strictly ascending within (0, 1].
type WordThresholds struct {
	Narrow       float64 `json:"narrow" yaml:"narrow"`
	Disruptive   float64 `json:"disruptive" yaml:"disruptive"`
	Debilitating float64 `json:"debilitating" yaml:"debilitating"`
}

// Config is the full scoring rubric.
type Config struct {
	Archetypes     map[string]Archetype `json:"archetypes" yaml:"archetypes"`
	LabelKeys      LabelKeys            `json:"labelKeys" yaml:"labelKeys"`
	Defaults       Defaults             `json:"defaults" yaml:"defaults"`
	WordThresholds WordThresholds       `json:"wordThresholds" yaml:"wordThresholds"`
	NamespaceRules []NamespaceRule      `json:"namespaceRules" yaml:"namespaceRules"`
	NameRules      []NameRule           `json:"nameRules" yaml:"nameRules"`
	KindRules      []KindRule           `json:"kindRules" yaml:"kindRules"`
	// MultiAgencyNamespaces are namespace globs whose workloads are treated as
	// multi-agency unless a more specific label says otherwise.
	MultiAgencyNamespaces []string `json:"multiAgencyNamespaces" yaml:"multiAgencyNamespaces"`
	// LEVEPSSThreshold is the EPSS score at or above which a finding is considered
	// Likely Exploitable (LEV). FedRAMP leaves the framework to the provider.
	LEVEPSSThreshold float64 `json:"levEpssThreshold" yaml:"levEpssThreshold"`

	// classOrigin/multiAgencyOrigin track which layer supplied the cluster-wide
	// Defaults values, for provenance reporting: "scoringConfig" (--scoring-config
	// file) or "configMap" (in-cluster ConfigMap). Empty means the built-in
	// rubric's value is still in effect. Unexported so config files cannot spoof
	// them.
	classOrigin       string
	multiAgencyOrigin string
}

// Input describes one finding-on-asset to be scored.
type Input struct {
	CVSSVector      string
	Severity        string
	Namespace       string
	WorkloadName    string
	WorkloadKind    string            // Kubernetes kind (Job, Deployment, ...); used by kindRules
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
	// MultiAgencySource records which signal set MultiAgency:
	// label | namespaceLabel | multiAgencyNamespaces | configMap | scoringConfig
	// | builtin | failsafe.
	MultiAgencySource string
	// Remediation (FedRAMP VDR-TFR-PVR)
	Class string
	// ClassSource records which signal set Class:
	// label | namespaceLabel | configMap | scoringConfig | builtin.
	ClassSource      string
	LEV              bool
	IRV              bool
	Column           string  // LEV+IRV | LEV+NIRV | NLEV
	DeadlineDays     float64 // < 0 means no FedRAMP deadline (PAIN-1)
	RemediationLabel string  // human-readable deadline (e.g. "12 hours", "32 days")
}

type embeddedPolicy struct {
	SchemaVersion int                  `yaml:"schemaVersion"`
	Archetypes    map[string]Archetype `yaml:"archetypes"`
}

func mustLoadBuiltinArchetypes() map[string]Archetype {
	var document embeddedPolicy
	if err := yaml.Unmarshal([]byte(builtinpolicy.VDRPolicyYAML()), &document); err != nil {
		panic(fmt.Sprintf("parse embedded VDR policy: %v", err))
	}
	if document.SchemaVersion != 1 {
		panic(fmt.Sprintf("embedded VDR policy schemaVersion = %d, want 1", document.SchemaVersion))
	}
	if len(document.Archetypes) == 0 {
		panic("embedded VDR policy has no archetypes")
	}
	for name, archetype := range document.Archetypes {
		if strings.TrimSpace(name) == "" {
			panic("embedded VDR policy contains an empty archetype name")
		}
		if strings.TrimSpace(archetype.Lens) == "" {
			panic(fmt.Sprintf("embedded VDR policy archetype %q has an empty lens", name))
		}
		for requirementName, requirement := range map[string]string{
			"cr": archetype.CR,
			"ir": archetype.IR,
			"ar": archetype.AR,
		} {
			if requirement != "H" && requirement != "M" && requirement != "L" {
				panic(fmt.Sprintf(
					"embedded VDR policy archetype %q has invalid %s requirement %q",
					name, requirementName, requirement,
				))
			}
		}
	}
	return document.Archetypes
}

// Default returns the built-in rubric: the archetype catalog loaded from the
// embedded canonical policy, standard label keys, an EPSS LEV threshold of
// 0.50, and a default Certification Class of B. It carries no namespace/name
// rules (those are tenant-specific) and assumes a single-tenant (single-agency)
// offering.
func Default() *Config {
	return &Config{
		Archetypes: mustLoadBuiltinArchetypes(),
		LabelKeys: LabelKeys{
			Archetype:   "vdr.fedramp.io/asset-archetype",
			AssetValue:  "vdr.fedramp.io/asset-value",
			MultiAgency: "vdr.fedramp.io/multi-agency",
			Class:       "vdr.fedramp.io/class",
		},
		Defaults: Defaults{
			MultiAgency: false,
			Archetype:   "unclassified",
			Class:       "B",
		},
		WordThresholds:   defaultWordThresholds,
		LEVEPSSThreshold: 0.50,
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
	pre := cfg.Defaults
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse scoring config %q: %w", path, err)
	}
	if cfg.Defaults.Class != pre.Class {
		cfg.classOrigin = "scoringConfig"
	}
	if cfg.Defaults.MultiAgency != pre.MultiAgency {
		cfg.multiAgencyOrigin = "scoringConfig"
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
	// The PAIN word thresholds are a governance/calibration decision and are
	// intentionally NOT overridable from the in-cluster ConfigMap (which a cluster
	// operator could change ad hoc); only --scoring-config or the built-in default
	// may set them. Preserve whatever is already in effect across the merge.
	savedThresholds := c.WordThresholds
	pre := c.Defaults
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
	c.WordThresholds = savedThresholds
	if c.Defaults.Class != pre.Class {
		c.classOrigin = "configMap"
	}
	if c.Defaults.MultiAgency != pre.MultiAgency {
		c.multiAgencyOrigin = "configMap"
	}
	if v := normalizeClass(data["class"]); v != "" {
		c.Defaults.Class = v
		c.classOrigin = "configMap"
	}
	av := data["assetValue"]
	if av == "" {
		av = data["asset-value"]
	}
	if v := normalizeAssetValue(av); v != "" {
		c.Defaults.AssetValue = v
	}
	ma, ok := data["multiAgency"]
	if !ok {
		ma = data["multi-agency"]
	}
	if b, ok := parseBoolLabel(ma); ok {
		c.Defaults.MultiAgency = b
		c.multiAgencyOrigin = "configMap"
	}
	return c.validate()
}

func (c *Config) validate() error {
	for i, r := range c.NamespaceRules {
		if r.Archetype == "" && r.AssetValue == "" {
			return fmt.Errorf("namespaceRules[%d] must set archetype or assetValue", i)
		}
		if r.Archetype != "" {
			if _, ok := c.Archetypes[r.Archetype]; !ok {
				return fmt.Errorf("namespaceRules[%d] references unknown archetype %q", i, r.Archetype)
			}
		}
		if r.AssetValue != "" && normalizeAssetValue(r.AssetValue) == "" {
			return fmt.Errorf("namespaceRules[%d] references unknown assetValue %q", i, r.AssetValue)
		}
	}
	for i, r := range c.NameRules {
		if r.Archetype == "" && r.AssetValue == "" {
			return fmt.Errorf("nameRules[%d] must set archetype or assetValue", i)
		}
		if r.Archetype != "" {
			if _, ok := c.Archetypes[r.Archetype]; !ok {
				return fmt.Errorf("nameRules[%d] references unknown archetype %q", i, r.Archetype)
			}
		}
		if r.AssetValue != "" && normalizeAssetValue(r.AssetValue) == "" {
			return fmt.Errorf("nameRules[%d] references unknown assetValue %q", i, r.AssetValue)
		}
	}
	for i, r := range c.KindRules {
		if r.Kind == "" {
			return fmt.Errorf("kindRules[%d] must set kind", i)
		}
		if r.Archetype == "" && r.AssetValue == "" {
			return fmt.Errorf("kindRules[%d] must set archetype or assetValue", i)
		}
		if r.Archetype != "" {
			if _, ok := c.Archetypes[r.Archetype]; !ok {
				return fmt.Errorf("kindRules[%d] references unknown archetype %q", i, r.Archetype)
			}
		}
		if r.AssetValue != "" && normalizeAssetValue(r.AssetValue) == "" {
			return fmt.Errorf("kindRules[%d] references unknown assetValue %q", i, r.AssetValue)
		}
	}
	if c.Defaults.AssetValue != "" && normalizeAssetValue(c.Defaults.AssetValue) == "" {
		return fmt.Errorf("defaults.assetValue %q must be one of H, M, L, High, Medium, Moderate, Low", c.Defaults.AssetValue)
	}
	if c.Defaults.Class != "" && normalizeClass(c.Defaults.Class) == "" {
		return fmt.Errorf("defaults.class %q must be one of A, B, C, D", c.Defaults.Class)
	}
	if c.Defaults.Archetype != "" {
		if _, ok := c.Archetypes[c.Defaults.Archetype]; !ok {
			return fmt.Errorf("defaults.archetype %q is not a known archetype", c.Defaults.Archetype)
		}
	}
	if t := c.WordThresholds; t != (WordThresholds{}) {
		if !(t.Narrow > 0 && t.Narrow < t.Disruptive && t.Disruptive < t.Debilitating && t.Debilitating <= 1) {
			return fmt.Errorf("wordThresholds must be strictly ascending within (0,1]: got narrow=%g disruptive=%g debilitating=%g", t.Narrow, t.Disruptive, t.Debilitating)
		}
	}
	return nil
}

// Score computes the PAIN and FedRAMP remediation deadline for a finding-on-asset.
func (c *Config) Score(in Input) Result {
	arch, source, assetValue, found := c.resolveClassification(in.Namespace, in.WorkloadName, in.WorkloadKind, in.Labels, in.NamespaceLabels)

	var a Archetype
	forceMulti := false
	if found {
		if assetValue != "" {
			a = archetypeForAssetValue(assetValue)
		} else {
			a = c.Archetypes[arch]
		}
	} else {
		// Fail-safe: an unclassified asset is treated as CR/IR/AR=High and
		// multi-agency=true, which floors the finding toward N5. Missing metadata
		// never lowers PAIN; it surfaces the asset for classification.
		a = Archetype{Lens: "control", CR: "H", IR: "H", AR: "H"}
		arch = c.Defaults.Archetype
		forceMulti = true
	}

	cImp, iImp, aImp, sevSource := impact(in.TechnicalImpact, in.CVSSVector, in.Severity)
	cr, ir, ar := weight(a.CR), weight(a.IR), weight(a.AR)
	isc := 1 - ((1 - cImp*cr) * (1 - iImp*ir) * (1 - aImp*ar))
	s := math.Min(isc, 0.915) / 0.915
	word := c.wordFromScalar(s)

	multi, multiSource := c.resolveMultiAgency(in.Namespace, in.Labels, in.NamespaceLabels)
	effectiveMulti := multi || forceMulti
	if forceMulti && !multi {
		multiSource = "failsafe"
	}
	tier := tierFromWord(word, effectiveMulti)

	// Remediation: FedRAMP VDR-TFR-PVR matrix[Class][PAIN][column].
	class, classSource := c.resolveClass(in.Labels, in.NamespaceLabels)
	lev := c.isLEV(in)
	irv := in.InternetReachable
	column := remediationColumn(lev, irv)
	days, label := remediationDeadline(class, tier, column)

	return Result{
		Tier:              tier,
		Word:              word,
		Severity:          s,
		Archetype:         arch,
		ArchetypeSource:   source,
		SeveritySource:    sevSource,
		CR:                normalizeReq(a.CR),
		IR:                normalizeReq(a.IR),
		AR:                normalizeReq(a.AR),
		MultiAgency:       effectiveMulti,
		MultiAgencySource: multiSource,
		Class:             class,
		ClassSource:       classSource,
		LEV:               lev,
		IRV:               irv,
		Column:            column,
		DeadlineDays:      days,
		RemediationLabel:  label,
	}
}

// resolveClassification prefers the richer asset-archetype path, then falls back
// to asset-value (H/M/L mapped uniformly across CR/IR/AR), then the default
// archetype/fail-safe path. The returned bool is false only for the fail-safe
// path (no usable signal).
func (c *Config) resolveClassification(namespace, name, kind string, labels, nsLabels map[string]string) (string, string, string, bool) {
	if arch, source, found := c.resolveArchetypeSignal(namespace, name, kind, labels, nsLabels); found || source == "label-unknown" {
		return arch, source, "", found
	}
	if value, source, found := c.resolveAssetValueSignal(namespace, name, kind, labels, nsLabels); found || source == "assetValueLabelUnknown" {
		return "asset-value-" + strings.ToLower(value), source, value, found
	}
	if c.Defaults.AssetValue != "" {
		if value := normalizeAssetValue(c.Defaults.AssetValue); value != "" {
			return "asset-value-" + strings.ToLower(value), "assetValueDefault", value, true
		}
	}
	if c.Defaults.Archetype != "" {
		if _, known := c.Archetypes[c.Defaults.Archetype]; known {
			return c.Defaults.Archetype, "default", "", true
		}
	}
	return "", "failsafe", "", false
}

func (c *Config) resolveArchetypeSignal(namespace, name, kind string, labels, nsLabels map[string]string) (string, string, bool) {
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
	for _, r := range c.KindRules {
		if !kindRuleMatches(r, namespace, name, kind) {
			continue
		}
		if _, known := c.Archetypes[r.Archetype]; known {
			return r.Archetype, "kindRule", true
		}
	}
	for _, r := range c.NamespaceRules {
		if ok, _ := path.Match(r.Match, namespace); ok {
			if _, known := c.Archetypes[r.Archetype]; known {
				return r.Archetype, "namespaceRule", true
			}
		}
	}
	return "", "", false
}

// kindRuleMatches reports whether a kind rule applies to the workload. Kind is
// required; namespace and name globs are optional (empty matches everything).
func kindRuleMatches(r KindRule, namespace, name, kind string) bool {
	if kind == "" {
		return false
	}
	if ok, _ := path.Match(r.Kind, kind); !ok {
		return false
	}
	if r.Namespace != "" {
		if ok, _ := path.Match(r.Namespace, namespace); !ok {
			return false
		}
	}
	if r.Match != "" {
		if ok, _ := path.Match(r.Match, name); !ok {
			return false
		}
	}
	return true
}

func (c *Config) resolveAssetValueSignal(namespace, name, kind string, labels, nsLabels map[string]string) (string, string, bool) {
	if v, ok := labels[c.LabelKeys.AssetValue]; ok {
		if value := normalizeAssetValue(v); value != "" {
			return value, "assetValueLabel", true
		}
		return "", "assetValueLabelUnknown", false
	}
	if v, ok := nsLabels[c.LabelKeys.AssetValue]; ok {
		if value := normalizeAssetValue(v); value != "" {
			return value, "assetValueNamespaceLabel", true
		}
		return "", "assetValueLabelUnknown", false
	}
	for _, r := range c.NameRules {
		if r.AssetValue == "" {
			continue
		}
		if r.Namespace != "" {
			if ok, _ := path.Match(r.Namespace, namespace); !ok {
				continue
			}
		}
		if ok, _ := path.Match(r.Match, name); ok {
			if value := normalizeAssetValue(r.AssetValue); value != "" {
				return value, "assetValueNameRule", true
			}
		}
	}
	for _, r := range c.KindRules {
		if r.AssetValue == "" {
			continue
		}
		if !kindRuleMatches(r, namespace, name, kind) {
			continue
		}
		if value := normalizeAssetValue(r.AssetValue); value != "" {
			return value, "assetValueKindRule", true
		}
	}
	for _, r := range c.NamespaceRules {
		if r.AssetValue == "" {
			continue
		}
		if ok, _ := path.Match(r.Match, namespace); ok {
			if value := normalizeAssetValue(r.AssetValue); value != "" {
				return value, "assetValueNamespaceRule", true
			}
		}
	}
	return "", "", false
}

// resolveMultiAgency: workload label > namespace label > multiAgencyNamespaces
// match > cluster default.
func (c *Config) resolveMultiAgency(namespace string, labels, nsLabels map[string]string) (bool, string) {
	if b, ok := parseBoolLabel(labels[c.LabelKeys.MultiAgency]); ok {
		return b, "label"
	}
	if b, ok := parseBoolLabel(nsLabels[c.LabelKeys.MultiAgency]); ok {
		return b, "namespaceLabel"
	}
	for _, glob := range c.MultiAgencyNamespaces {
		if ok, _ := path.Match(glob, namespace); ok {
			return true, "multiAgencyNamespaces"
		}
	}
	if c.multiAgencyOrigin != "" {
		return c.Defaults.MultiAgency, c.multiAgencyOrigin
	}
	return c.Defaults.MultiAgency, "builtin"
}

// resolveClass: workload label > namespace label > cluster default > "B".
func (c *Config) resolveClass(labels, nsLabels map[string]string) (string, string) {
	if v := normalizeClass(labels[c.LabelKeys.Class]); v != "" {
		return v, "label"
	}
	if v := normalizeClass(nsLabels[c.LabelKeys.Class]); v != "" {
		return v, "namespaceLabel"
	}
	if v := normalizeClass(c.Defaults.Class); v != "" {
		if c.classOrigin != "" {
			return v, c.classOrigin
		}
		return v, "builtin"
	}
	return "B", "builtin"
}

// isLEV implements the method's LEV union — any one suffices, with no weighting
// among them: EPSS at or above the governed threshold, observed exploitation,
// or the FRD-LEV vector floor. The floor implements FedRAMP's note that "any
// vulnerability that an automated unauthenticated system can exploit over the
// internet is a likely exploitable vulnerability": the finding is
// internet-reachable via direct exposure and its CVSS vector permits
// low-complexity, unauthenticated automation (AV:N/AC:L/PR:N/UI:N). An AC:H
// finding does not enter LEV through the floor alone; EPSS or observed
// exploitation independently place it in LEV.
func (c *Config) isLEV(in Input) bool {
	if strings.EqualFold(strings.TrimSpace(in.Exploitation), "active") {
		return true
	}
	if in.EPSS >= 0 && in.EPSS >= c.LEVEPSSThreshold {
		return true
	}
	return in.InternetReachable && permitsUnauthenticatedAutomation(in.CVSSVector)
}

// permitsUnauthenticatedAutomation reports whether the CVSS vector permits
// low-complexity, unauthenticated automation: AV:N, AC:L, PR:N, UI:N. The
// metric keys are shared by v3.x and v4.0 (v4's UI:P/UI:A count as interaction
// required). A missing or unparsable vector never fires the floor, and CVSS v2
// vectors (no PR/UI metrics) are treated the same conservative way.
func permitsUnauthenticatedAutomation(vector string) bool {
	m := parseVector(vector)
	return m["AV"] == "N" && m["AC"] == "L" && m["PR"] == "N" && m["UI"] == "N"
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

func normalizeAssetValue(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "h", "high":
		return "high"
	case "m", "medium", "moderate":
		return "medium"
	case "l", "low":
		return "low"
	default:
		return ""
	}
}

func archetypeForAssetValue(value string) Archetype {
	switch normalizeAssetValue(value) {
	case "high":
		return Archetype{Lens: "asset-value", CR: "H", IR: "H", AR: "H"}
	case "medium":
		return Archetype{Lens: "asset-value", CR: "M", IR: "M", AR: "M"}
	case "low":
		return Archetype{Lens: "asset-value", CR: "L", IR: "L", AR: "L"}
	default:
		return Archetype{Lens: "asset-value", CR: "H", IR: "H", AR: "H"}
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

// defaultWordThresholds is the built-in calibration: Minimal < 0.25, Narrow <
// 0.55, Disruptive < 0.80, else Debilitating. The cut points are the model's one
// calibratable judgment and may be overridden via config (wordThresholds).
var defaultWordThresholds = WordThresholds{Narrow: 0.25, Disruptive: 0.55, Debilitating: 0.80}

// wordFromScalar maps the normalized environmental impact scalar to a FedRAMP
// customer-effect word using the configured thresholds, falling back to the
// built-in defaults when they are unset (zero-value config).
func (c *Config) wordFromScalar(s float64) string {
	t := c.WordThresholds
	if t.Narrow == 0 && t.Disruptive == 0 && t.Debilitating == 0 {
		t = defaultWordThresholds
	}
	switch {
	case s < t.Narrow:
		return "Minimal"
	case s < t.Disruptive:
		return "Narrow"
	case s < t.Debilitating:
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
