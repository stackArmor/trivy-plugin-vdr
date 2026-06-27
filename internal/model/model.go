package model

import "time"

type Inventory struct {
	ContextName string              `json:"contextName"`
	Resources   []ResourceInventory `json:"resources"`
	Images      []ImageInventory    `json:"images"`
	// Namespaces maps a namespace name to its object labels. Used to resolve
	// namespace-level FedRAMP metadata (asset-archetype, multi-agency, class).
	Namespaces map[string]map[string]string `json:"namespaces,omitempty"`
	// ClusterDefaults holds cluster-wide FedRAMP metadata read from the cluster
	// ConfigMap (e.g. class, multiAgency). Not serialized in the report.
	ClusterDefaults map[string]string `json:"-"`
	// Warnings holds best-effort collection warnings (e.g. a missing cluster
	// ConfigMap) to be surfaced into the report. Not serialized here.
	Warnings []string `json:"-"`
}

type ImageInventory struct {
	ImageRef string `json:"imageRef"`
	// NormalizedImage is the image reference without tag or digest for grouping and display only.
	// ImageRef remains the canonical scan/deduplication key.
	NormalizedImage string        `json:"normalizedImage,omitempty"`
	Resources       []ResourceRef `json:"resources"`
}

type ResourceInventory struct {
	Resource   ResourceRef       `json:"resource"`
	Labels     map[string]string `json:"labels,omitempty"`
	Images     []ContainerImage  `json:"images"`
	Conditions []string          `json:"conditions,omitempty"`
}

type ResourceRef struct {
	APIVersion    string `json:"apiVersion,omitempty"`
	Kind          string `json:"kind"`
	Namespace     string `json:"namespace,omitempty"`
	Name          string `json:"name"`
	ContainerName string `json:"containerName,omitempty"`
	ContainerType string `json:"containerType,omitempty"`
	RestartPolicy string `json:"restartPolicy,omitempty"`
}

type ContainerImage struct {
	Name          string `json:"name"`
	ContainerType string `json:"containerType"`
	ImageRef      string `json:"imageRef"`
	// NormalizedImage is the image reference without tag or digest for grouping and display only.
	// ImageRef remains the canonical scan/deduplication key.
	NormalizedImage string             `json:"normalizedImage,omitempty"`
	RestartPolicy   string             `json:"restartPolicy,omitempty"`
	Security        *ContainerSecurity `json:"security,omitempty"`
}

type ContainerSecurity struct {
	Privileged             *bool            `json:"privileged,omitempty"`
	CapabilitiesAdd        []string         `json:"capabilitiesAdd,omitempty"`
	CapabilitiesDrop       []string         `json:"capabilitiesDrop,omitempty"`
	ReadOnlyRootFilesystem *bool            `json:"readOnlyRootFilesystem,omitempty"`
	SeccompProfile         *SecurityProfile `json:"seccompProfile,omitempty"`
	AppArmorProfile        *SecurityProfile `json:"appArmorProfile,omitempty"`
}

type SecurityProfile struct {
	Type             string `json:"type,omitempty"`
	LocalhostProfile string `json:"localhostProfile,omitempty"`
}

type Finding struct {
	ID               string   `json:"id"`
	ImageRef         string   `json:"imageRef"`
	NormalizedImage  string   `json:"normalizedImage,omitempty"`
	PackageName      string   `json:"packageName,omitempty"`
	InstalledVersion string   `json:"installedVersion,omitempty"`
	FixedVersion     string   `json:"fixedVersion,omitempty"`
	Severity         string   `json:"severity"`
	Status           string   `json:"status,omitempty"`
	Title            string   `json:"title,omitempty"`
	Description      string   `json:"description,omitempty"`
	References       []string `json:"references,omitempty"`
	// CVSSVector is the preferred CVSS base vector (v3, else v4) from the scanner.
	// It feeds the report's automatability fallback when CISA Vulnrichment has no
	// record for the CVE.
	CVSSVector   string        `json:"cvssVector,omitempty"`
	EPSS         *EPSS         `json:"epss,omitempty"`
	Vulnrichment *Vulnrichment `json:"vulnrichment,omitempty"`
	Exposure     *Exposure     `json:"exposure,omitempty"`
	// AffectedResources is the internal list of resources using this image. It is
	// not serialized; the public, richer representation is Affected (each resource
	// plus its exposure).
	AffectedResources []ResourceRef `json:"-"`
	Affected          []Affected    `json:"affected,omitempty"`
	// Pain is the FedRAMP Potential Agency Impact (N1-N5) for this finding. In the
	// findings view it is the worst PAIN across all affected resources; in the
	// resources view it is the PAIN for the single scoped resource.
	Pain *Pain `json:"pain,omitempty"`
	// Remediation is the FedRAMP VDR-TFR-PVR deadline for this finding, paired with
	// Pain (worst across affected in the findings view; per-resource otherwise).
	Remediation *Remediation `json:"remediation,omitempty"`
}

type EPSS struct {
	Score        float64 `json:"score"`
	Percentile   float64 `json:"percentile"`
	ModelVersion string  `json:"modelVersion,omitempty"`
	ScoreDate    string  `json:"scoreDate,omitempty"`
}

type Vulnrichment struct {
	Exploitation    string `json:"exploitation,omitempty"`
	Automatable     string `json:"automatable,omitempty"`
	TechnicalImpact string `json:"technicalImpact,omitempty"`
	SourceURL       string `json:"sourceUrl,omitempty"`
}

type Exposure struct {
	InternetAccessible bool              `json:"internetAccessible"`
	Provider           string            `json:"provider,omitempty"`
	RouteKind          string            `json:"routeKind,omitempty"`
	RouteName          string            `json:"routeName,omitempty"`
	Protection         *AccessProtection `json:"protection,omitempty"`
	Evidence           []string          `json:"evidence,omitempty"`
}

type AccessProtection struct {
	Type     string `json:"type,omitempty"`
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type Affected struct {
	Resource    ResourceRef  `json:"resource"`
	Exposure    *Exposure    `json:"exposure,omitempty"`
	Pain        *Pain        `json:"pain,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"`
}

// Remediation is the FedRAMP Rev5 VDR-TFR-PVR remediation deadline for a finding
// on an asset, selected by the provider Certification Class, the PAIN rating, and
// the exploitability column (LEV+IRV | LEV+NIRV | NLEV).
type Remediation struct {
	Class        string  `json:"class"`        // A|B|C|D
	Column       string  `json:"column"`       // LEV+IRV|LEV+NIRV|NLEV
	LEV          bool    `json:"lev"`          // likely exploitable
	IRV          bool    `json:"irv"`          // internet reachable
	DeadlineDays float64 `json:"deadlineDays"` // < 0 => no FedRAMP deadline (PAIN-1)
	Deadline     string  `json:"deadline"`     // human-readable (e.g. "12 hours")
}

// Pain is the FedRAMP Rev5 VDR Potential Agency Impact rating (N1-N5) for a
// finding on a specific asset. Tier is derived from the CVSS impact vector
// weighted by the asset archetype's CR/IR/AR requirements and the agency scope.
type Pain struct {
	Tier            string  `json:"tier"`                     // N1..N5
	Word            string  `json:"word"`                     // Minimal|Narrow|Disruptive|Debilitating
	Severity        float64 `json:"severity"`                 // normalized environmental impact scalar 0..1
	Archetype       string  `json:"archetype"`                // resolved asset-archetype
	ArchetypeSource string  `json:"archetypeSource"`          // label|namespaceLabel|nameRule|namespaceRule|default|failsafe
	SeveritySource  string  `json:"severitySource,omitempty"` // technicalImpact|cvss|severity
	CR              string  `json:"cr"`                       // confidentiality requirement (L|M|H)
	IR              string  `json:"ir"`                       // integrity requirement (L|M|H)
	AR              string  `json:"ar"`                       // availability requirement (L|M|H)
	MultiAgency     bool    `json:"multiAgency"`              // effective scope used (incl. fail-safe)
}

type Report struct {
	GeneratedAt time.Time `json:"generatedAt"`
	// ContextName is the Kubernetes context (kubectx) the inventory was collected
	// from. Shown in the report header.
	ContextName string `json:"contextName,omitempty"`
	// Class is the cluster-wide FedRAMP Certification Class (A/B/C/D) in effect for
	// scoring. Shown in the report header.
	Class     string           `json:"class,omitempty"`
	Summary   Summary          `json:"summary"`
	Findings  []Finding        `json:"findings,omitempty"`
	Resources []ResourceReport `json:"resources,omitempty"`
	Warnings  []string         `json:"warnings,omitempty"`
}

type ResourceReport struct {
	Resource ResourceRef       `json:"resource"`
	Images   []ContainerImage  `json:"images,omitempty"`
	Exposure *Exposure         `json:"exposure,omitempty"`
	Findings []Finding         `json:"findings"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type Summary struct {
	Contexts           int            `json:"contexts,omitempty"`
	Namespaces         int            `json:"namespaces,omitempty"`
	Resources          int            `json:"resources"`
	Images             int            `json:"images"`
	Findings           int            `json:"findings"`
	BySeverity         map[string]int `json:"bySeverity,omitempty"`
	InternetAccessible int            `json:"internetAccessible,omitempty"`
}
