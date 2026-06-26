package model

import "time"

type Inventory struct {
	ContextName string              `json:"contextName"`
	Resources   []ResourceInventory `json:"resources"`
	Images      []ImageInventory    `json:"images"`
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
	ID               string        `json:"id"`
	ImageRef         string        `json:"imageRef"`
	NormalizedImage  string        `json:"normalizedImage,omitempty"`
	PackageName      string        `json:"packageName,omitempty"`
	InstalledVersion string        `json:"installedVersion,omitempty"`
	FixedVersion     string        `json:"fixedVersion,omitempty"`
	Severity         string        `json:"severity"`
	Status           string        `json:"status,omitempty"`
	Title            string        `json:"title,omitempty"`
	Description      string        `json:"description,omitempty"`
	References       []string      `json:"references,omitempty"`
	EPSS             *EPSS         `json:"epss,omitempty"`
	Vulnrichment     *Vulnrichment `json:"vulnrichment,omitempty"`
	Exposure         *Exposure     `json:"exposure,omitempty"`
	// AffectedResources is the internal list of resources using this image. It is
	// not serialized; the public, richer representation is Affected (each resource
	// plus its exposure).
	AffectedResources []ResourceRef `json:"-"`
	Affected          []Affected    `json:"affected,omitempty"`
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
	Resource ResourceRef `json:"resource"`
	Exposure *Exposure   `json:"exposure,omitempty"`
}

type Report struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Summary     Summary          `json:"summary"`
	Findings    []Finding        `json:"findings,omitempty"`
	Resources   []ResourceReport `json:"resources,omitempty"`
	Warnings    []string         `json:"warnings,omitempty"`
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
