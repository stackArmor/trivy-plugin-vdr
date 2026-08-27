package model

import "time"

type Inventory struct {
	ContextName string              `json:"contextName"`
	Resources   []ResourceInventory `json:"resources"`
	Images      []ImageInventory    `json:"images"`
	// Namespaces maps a namespace name to its object labels. Used to resolve
	// namespace-level FedRAMP metadata (security-impact profile, multi-agency, class).
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
	SkipDirs        []string      `json:"skipDirs,omitempty"`
}

type ResourceInventory struct {
	Resource ResourceRef       `json:"resource"`
	Labels   map[string]string `json:"labels,omitempty"`
	// PodLabels are the labels on the actual pod or pod template. Kubernetes
	// Service selectors are evaluated against these labels, never controller
	// metadata labels. A non-nil empty map means the pod template has no labels.
	PodLabels        map[string]string `json:"podLabels,omitempty"`
	ProviderMetadata map[string]string `json:"providerMetadata,omitempty"`
	Images           []ContainerImage  `json:"images"`
	Conditions       []string          `json:"conditions,omitempty"`
	Runtime          *RuntimeMetadata  `json:"runtime,omitempty"`
	// Posture holds neutral Kubernetes security-posture facts observed for this
	// workload (see WorkloadPosture). It is captured read-only for a downstream
	// evaluator; no scoring or control semantics are applied here.
	Posture *WorkloadPosture `json:"posture,omitempty"`
}

type RuntimeMetadata struct {
	Status   string   `json:"status,omitempty"`
	Observed bool     `json:"observed,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// WorkloadPosture is a read-only, neutral capture of Kubernetes security-posture
// facts observed directly on a workload's pod template and the namespace policy
// objects that select it. Every field is a fact read verbatim from a Kubernetes
// object; no cloud-provider control, product, or scoring interpretation is applied
// here (e.g. no IMDS/metadata/identity-provider inference — only the raw CIDRs and
// podspec values). It is emitted for a downstream evaluator to interpret.
// Collection is best-effort and fail-open: fields backed by an object the
// collector could not read (RBAC denied) are left unset.
type WorkloadPosture struct {
	SecurityContext *PostureSecurityContext `json:"securityContext,omitempty"`
	Workload        *PostureWorkload        `json:"workload,omitempty"`
	Identity        *PostureIdentity        `json:"identity,omitempty"`
	Volumes         *PostureVolumes         `json:"volumes,omitempty"`
	NetworkPolicy   *PostureNetworkPolicy   `json:"networkPolicy,omitempty"`
}

// PostureSecurityContext captures pod/container securityContext facts, aggregated
// across the workload's app (non-init) containers.
type PostureSecurityContext struct {
	// ReadOnlyRootFilesystem is true only when every app container sets
	// securityContext.readOnlyRootFilesystem=true.
	ReadOnlyRootFilesystem bool `json:"readOnlyRootFilesystem,omitempty"`
	// RunAsNonRoot is true only when every app container runs as non-root
	// (container securityContext.runAsNonRoot, else the pod-level value).
	RunAsNonRoot bool `json:"runAsNonRoot,omitempty"`
	// Privileged is true when any app container sets
	// securityContext.privileged=true.
	Privileged bool `json:"privileged,omitempty"`
	// AllowPrivilegeEscalation is true when any app container sets
	// securityContext.allowPrivilegeEscalation=true.
	AllowPrivilegeEscalation bool `json:"allowPrivilegeEscalation,omitempty"`
	// DroppedCapabilities lists the capabilities dropped by every app container
	// (the intersection of each container's securityContext.capabilities.drop),
	// sorted.
	DroppedCapabilities []string `json:"droppedCapabilities,omitempty"`
	// SeccompProfileType is the seccompProfile.type in effect for the workload:
	// the pod-level value, else the type shared by all app containers.
	SeccompProfileType string `json:"seccompProfileType,omitempty"`
}

// PostureWorkload captures workload-shape and availability facts.
type PostureWorkload struct {
	// Replicas is the workload's declared replica count (Deployment/StatefulSet).
	// Nil for kinds without a replica field (Pod/DaemonSet/Job/CronJob).
	Replicas *int32 `json:"replicas,omitempty"`
	// HasPodDisruptionBudget is true when a PodDisruptionBudget in the namespace
	// selects this workload's pods.
	HasPodDisruptionBudget bool `json:"hasPodDisruptionBudget,omitempty"`
	// ZoneSpread is true when the pod template requires spread across
	// topology.kubernetes.io/zone (a DoNotSchedule topologySpreadConstraint or a
	// required pod anti-affinity term on the zone key).
	ZoneSpread bool `json:"zoneSpread,omitempty"`
	// LivenessProbe is true when any app container declares a livenessProbe.
	LivenessProbe bool `json:"livenessProbe,omitempty"`
	// ReadinessProbe is true when any app container declares a readinessProbe.
	ReadinessProbe bool `json:"readinessProbe,omitempty"`
}

// PostureIdentity captures pod identity/secret-sourcing facts.
type PostureIdentity struct {
	// ServiceAccountName is spec.serviceAccountName.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// AutomountServiceAccountToken is spec.automountServiceAccountToken verbatim
	// (nil when unset, preserving the tri-state).
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`
	// EnvFromSecretRef is true when any container sources env from a Secret
	// (env.valueFrom.secretKeyRef or envFrom.secretRef).
	EnvFromSecretRef bool `json:"envFromSecretRef,omitempty"`
}

// PostureVolumes captures writable-storage facts.
type PostureVolumes struct {
	// WritableVolumeMounts lists the container mount paths that are mounted
	// read-write onto a writable-backed volume (emptyDir/PVC/ephemeral/hostPath),
	// sorted.
	WritableVolumeMounts []string `json:"writableVolumeMounts,omitempty"`
}

// PostureNetworkPolicy captures raw NetworkPolicy facts for the policies that
// select this workload. CIDRs and IPBlock.except entries are recorded verbatim;
// no address (e.g. link-local metadata) is interpreted.
type PostureNetworkPolicy struct {
	// SelectedByEgressPolicy is true when an Egress-typed NetworkPolicy selects
	// this workload's pods.
	SelectedByEgressPolicy bool `json:"selectedByEgressPolicy,omitempty"`
	// EgressDefaultDeny is true when a selecting Egress policy declares no egress
	// rules (which denies all egress).
	EgressDefaultDeny bool `json:"egressDefaultDeny,omitempty"`
	// EgressAllowedCIDRs are the raw ipBlock.cidr allow-list entries across the
	// selecting egress rules, sorted and de-duplicated.
	EgressAllowedCIDRs []string `json:"egressAllowedCidrs,omitempty"`
	// EgressDeniedByExcept are the raw ipBlock.except entries across the selecting
	// egress rules, sorted and de-duplicated.
	EgressDeniedByExcept []string `json:"egressDeniedByExcept,omitempty"`
	// SelectedByIngressPolicy is true when an Ingress-typed NetworkPolicy selects
	// this workload's pods.
	SelectedByIngressPolicy bool `json:"selectedByIngressPolicy,omitempty"`
}

type ResourceRef struct {
	APIVersion    string `json:"apiVersion,omitempty"`
	Kind          string `json:"kind"`
	Provider      string `json:"provider,omitempty"`
	Project       string `json:"project,omitempty"`
	Region        string `json:"region,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	Name          string `json:"name"`
	UID           string `json:"uid,omitempty"`
	CanonicalID   string `json:"canonicalId,omitempty"`
	DisplayID     string `json:"displayId,omitempty"`
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
	// Sandbox records a platform-enforced isolation boundary around the
	// container, when one is known: "gVisor" (Cloud Run gen1 user-space kernel)
	// or "microVM" (Cloud Run gen2). Empty when the platform does not declare
	// one (Kubernetes, ECS) or the execution environment is unspecified.
	Sandbox string `json:"sandbox,omitempty"`
}

type SecurityProfile struct {
	Type             string `json:"type,omitempty"`
	LocalhostProfile string `json:"localhostProfile,omitempty"`
}

type Finding struct {
	ID              string `json:"id"`
	ImageRef        string `json:"imageRef"`
	NormalizedImage string `json:"normalizedImage,omitempty"`
	// ImageRefs lists every distinct image reference the duplicates merged by
	// report deduplication (on by default; disable with --no-dedupe) were found
	// in, sorted. Populated only when duplicates span more than one image;
	// ImageRef remains the survivor's image.
	ImageRefs           []string                 `json:"imageRefs,omitempty"`
	Target              string                   `json:"target,omitempty"`
	TargetClass         string                   `json:"targetClass,omitempty"`
	TargetType          string                   `json:"targetType,omitempty"`
	PackageID           string                   `json:"packageId,omitempty"`
	PackageName         string                   `json:"packageName,omitempty"`
	PackagePURL         string                   `json:"packagePurl,omitempty"`
	PackageUID          string                   `json:"packageUid,omitempty"`
	PackagePath         string                   `json:"packagePath,omitempty"`
	PackageRelationship string                   `json:"packageRelationship,omitempty"`
	InstalledVersion    string                   `json:"installedVersion,omitempty"`
	FixedVersion        string                   `json:"fixedVersion,omitempty"`
	Severity            string                   `json:"severity"`
	SeveritySource      string                   `json:"severitySource,omitempty"`
	VendorSeverity      map[string]string        `json:"vendorSeverity,omitempty"`
	Status              string                   `json:"status,omitempty"`
	Title               string                   `json:"title,omitempty"`
	Description         string                   `json:"description,omitempty"`
	DataSource          *VulnerabilityDataSource `json:"dataSource,omitempty"`
	PrimaryURL          string                   `json:"primaryUrl,omitempty"`
	ScannerFingerprint  string                   `json:"scannerFingerprint,omitempty"`
	VendorIDs           []string                 `json:"vendorIds,omitempty"`
	References          []string                 `json:"references,omitempty"`
	PublishedDate       *time.Time               `json:"publishedDate,omitempty"`
	LastModifiedDate    *time.Time               `json:"lastModifiedDate,omitempty"`
	// CVSSVector is the preferred CVSS base vector (v3, else v4) from the scanner.
	// It feeds the report's automatability fallback when CISA Vulnrichment has no
	// record for the CVE.
	CVSSVector string `json:"cvssVector,omitempty"`
	// CWEs holds the CWE identifiers assigned to this finding's CVE (e.g.
	// "CWE-787"), surfaced from the per-CVE enrichment record. It is empty when no
	// specific CWE is known; the generic placeholders NVD-CWE-noinfo/NVD-CWE-Other
	// are never included.
	CWEs         []string      `json:"cwes,omitempty"`
	EPSS         *EPSS         `json:"epss,omitempty"`
	Vulnrichment *Vulnrichment `json:"vulnrichment,omitempty"`
	// ChainTaxonomy preserves the path-level CWE -> CAPEC -> ATT&CK evidence for
	// this CVE. It is informational and does not affect PAIN, IRV, or remediation.
	ChainTaxonomy *ChainTaxonomyEvidence `json:"chainTaxonomy,omitempty"`
	Exposure      *Exposure              `json:"exposure,omitempty"`
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
	// Suppressed marks a scanner finding that has been dispositioned by VEX or a
	// similar source and is not part of the active remediation queue.
	Suppressed  bool         `json:"suppressed,omitempty"`
	Suppression *Suppression `json:"suppression,omitempty"`
	// WouldHaveBeenPain/Remediation are informational values for suppressed
	// findings: the active PAIN/deadline that would have applied if the finding had
	// not been dispositioned as suppressed.
	WouldHaveBeenPain        *Pain        `json:"wouldHaveBeenPain,omitempty"`
	WouldHaveBeenRemediation *Remediation `json:"wouldHaveBeenRemediation,omitempty"`
}

type VulnerabilityDataSource struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	URL    string `json:"url,omitempty"`
	BaseID string `json:"baseId,omitempty"`
}

type Suppression struct {
	Source          string `json:"source,omitempty"`
	Status          string `json:"status,omitempty"`
	Justification   string `json:"justification,omitempty"`
	ImpactStatement string `json:"impactStatement,omitempty"`
	StatementSource string `json:"statementSource,omitempty"`
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
	// CWEs holds the CWE identifiers resolved for the CVE (source precedence:
	// CISA Vulnrichment ADP problemTypes, then NVD CVE-record weaknesses),
	// skipping the useless NVD-CWE-noinfo/NVD-CWE-Other assignments.
	CWEs      []string `json:"cwes,omitempty"`
	SourceURL string   `json:"sourceUrl,omitempty"`
}

// ChainTaxonomyEvidence is the offline taxonomy projection for one CVE. A
// mapped status means at least one active Standard/Detailed CAPEC pattern was
// found. Unknown means the source CWE or an eligible CAPEC mapping was absent;
// it is not evidence that the CVE cannot participate in a chain.
type ChainTaxonomyEvidence struct {
	Status              string              `json:"status"` // mapped|unknown
	TaxonomyRole        string              `json:"taxonomyRole"`
	Ambiguity           string              `json:"ambiguity"`         // none|multiple_paths|mixed_roles
	PredecessorStatus   string              `json:"predecessorStatus"` // present|not_declared|unknown
	SuccessorStatus     string              `json:"successorStatus"`   // present|not_declared|unknown
	CAPECIDs            []string            `json:"capecIds,omitempty"`
	ATTACKTechniqueIDs  []string            `json:"attackTechniqueIds,omitempty"`
	ATTACKTactics       []string            `json:"attackTactics,omitempty"`
	PredecessorCAPECIDs []string            `json:"predecessorCapecIds,omitempty"`
	SuccessorCAPECIDs   []string            `json:"successorCapecIds,omitempty"`
	Paths               []ChainTaxonomyPath `json:"paths,omitempty"`
	ReasonCodes         []string            `json:"reasonCodes"`
	PolicyVersion       string              `json:"policyVersion"`
}

// ChainTaxonomyPath retains the specific CWE/CAPEC path that contributed
// taxonomy evidence. It deliberately avoids flattening unrelated CAPEC paths
// into one unreviewable union.
type ChainTaxonomyPath struct {
	CWEID               string                 `json:"cweId"`
	CAPECID             string                 `json:"capecId"`
	CAPECName           string                 `json:"capecName"`
	Abstraction         string                 `json:"abstraction"`
	ATTACKTechniques    []ChainATTACKTechnique `json:"attackTechniques,omitempty"`
	PredecessorCAPECIDs []string               `json:"predecessorCapecIds,omitempty"`
	SuccessorCAPECIDs   []string               `json:"successorCapecIds,omitempty"`
	ConsequenceImpacts  []string               `json:"consequenceImpacts,omitempty"`
}

// ChainATTACKTechnique is one CAPEC taxonomy mapping resolved against the
// official Enterprise ATT&CK STIX corpus.
type ChainATTACKTechnique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Tactics []string `json:"tactics,omitempty"`
}

// ChainCatalogMetadata identifies the exact generated corpus snapshot embedded
// in the plugin.
type ChainCatalogMetadata struct {
	SchemaVersion string `json:"schemaVersion"`
	CAPECVersion  string `json:"capecVersion"`
	CAPECDate     string `json:"capecDate,omitempty"`
	CAPECSHA256   string `json:"capecSha256"`
	ATTACKVersion string `json:"attackVersion"`
	ATTACKDate    string `json:"attackDate,omitempty"`
	ATTACKSHA256  string `json:"attackSha256"`
}

// CAPECTransitionCandidate is an aggregated, pattern-level candidate transition
// between two active CVEs observed on the same exact resource. It is emitted
// only for an internet-reachable, AV:N/PR:N upstream CVE and an explicit CAPEC
// CanPrecede edge to a downstream CVE's mapped path. The downstream CVSS access
// metrics are retained as context but do not gate the relationship. It does not
// change either finding's IRV or remediation deadline.
type CAPECTransitionCandidate struct {
	Resource                   ResourceRef             `json:"resource"`
	CandidateClass             string                  `json:"candidateClass"`
	Upstream                   CAPECTransitionEndpoint `json:"upstream"`
	Downstream                 CAPECTransitionEndpoint `json:"downstream"`
	SourceCAPECID              string                  `json:"sourceCapecId"`
	SourceCAPECName            string                  `json:"sourceCapecName"`
	TargetCAPECID              string                  `json:"targetCapecId"`
	TargetCAPECName            string                  `json:"targetCapecName"`
	Relationship               string                  `json:"relationship"`
	UpstreamInternetAccessible bool                    `json:"upstreamInternetAccessible"`
	SourceConsequenceImpacts   []string                `json:"sourceConsequenceImpacts,omitempty"`
	TargetPrerequisites        []string                `json:"targetPrerequisites,omitempty"`
	EvidenceLevel              string                  `json:"evidenceLevel"`
	Confidence                 string                  `json:"confidence"`
	ReviewRequired             bool                    `json:"reviewRequired"`
	ReasonCodes                []string                `json:"reasonCodes"`
	PolicyVersion              string                  `json:"policyVersion"`
}

// CAPECTransitionEndpoint aggregates every package occurrence and CWE path for
// one CVE endpoint without duplicating its complete vulnerability records.
type CAPECTransitionEndpoint struct {
	ID                 string                            `json:"cveId"`
	Role               string                            `json:"role"`
	Findings           []CAPECTransitionFindingReference `json:"findings,omitempty"`
	CWEIDs             []string                          `json:"cweIds,omitempty"`
	AttackVector       string                            `json:"attackVector"`
	PrivilegesRequired string                            `json:"privilegesRequired"`
}

// CAPECTransitionFindingReference identifies one package occurrence of a CVE
// endpoint without duplicating its complete vulnerability record.
type CAPECTransitionFindingReference struct {
	PackageName      string `json:"packageName,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	ImageRef         string `json:"imageRef,omitempty"`
}

type Exposure struct {
	InternetAccessible bool `json:"internetAccessible"`
	// AssessmentBasis distinguishes live-cluster observations from static Helm
	// deployment intent. Helm scans set this to "declared" because rendered
	// manifests do not contain load-balancer provisioning or runtime status.
	AssessmentBasis string            `json:"assessmentBasis,omitempty"`
	Provider        string            `json:"provider,omitempty"`
	RouteKind       string            `json:"routeKind,omitempty"`
	RouteName       string            `json:"routeName,omitempty"`
	Routes          []RouteMetadata   `json:"routes,omitempty"`
	Protection      *AccessProtection `json:"protection,omitempty"`
	Evidence        []string          `json:"evidence,omitempty"`
}

type RouteMetadata struct {
	Kind                       string         `json:"kind,omitempty"`
	Namespace                  string         `json:"namespace,omitempty"`
	Name                       string         `json:"name,omitempty"`
	Hostnames                  []string       `json:"hostnames,omitempty"`
	Paths                      []RoutePath    `json:"paths,omitempty"`
	Headers                    []RouteHeader  `json:"headers,omitempty"`
	Rewrites                   []RouteRewrite `json:"rewrites,omitempty"`
	BackendService             string         `json:"backendService,omitempty"`
	BackendNamespace           string         `json:"backendNamespace,omitempty"`
	BackendServicePort         int32          `json:"backendServicePort,omitempty"`
	BackendServicePortName     string         `json:"backendServicePortName,omitempty"`
	BackendTargetPort          string         `json:"backendTargetPort,omitempty"`
	BackendAppProtocol         string         `json:"backendAppProtocol,omitempty"`
	BackendServicePortProtocol string         `json:"backendServicePortProtocol,omitempty"`
	URLMap                     string         `json:"urlMap,omitempty"`
	TargetProxy                string         `json:"targetProxy,omitempty"`
	LoadBalancerIP             string         `json:"loadBalancerIp,omitempty"`
	FrontendProtocol           string         `json:"frontendProtocol,omitempty"`
	BackendProtocol            string         `json:"backendProtocol,omitempty"`
	BackendProtocolVersion     string         `json:"backendProtocolVersion,omitempty"`
	BackendTLS                 bool           `json:"backendTls,omitempty"`
	ALPN                       []string       `json:"alpn,omitempty"`
	ALPNPolicy                 string         `json:"alpnPolicy,omitempty"`
}

type RoutePath struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type RouteHeader struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

type RouteRewrite struct {
	HostnameReplace           string `json:"hostnameReplace,omitempty"`
	PathReplaceFullPath       string `json:"pathReplaceFullPath,omitempty"`
	PathReplacePrefixMatch    string `json:"pathReplacePrefixMatch,omitempty"`
	RequestRedirectHostname   string `json:"requestRedirectHostname,omitempty"`
	RequestRedirectPath       string `json:"requestRedirectPath,omitempty"`
	RequestRedirectPrefix     string `json:"requestRedirectPrefix,omitempty"`
	RequestRedirectScheme     string `json:"requestRedirectScheme,omitempty"`
	RequestRedirectStatusCode int32  `json:"requestRedirectStatusCode,omitempty"`
}

type AccessProtection struct {
	Type           string          `json:"authProxyType,omitempty"`
	Enabled        bool            `json:"authProxyEnabled"`
	Provider       string          `json:"provider,omitempty"`
	Evidence       string          `json:"evidence,omitempty"`
	SecurityPolicy *SecurityPolicy `json:"securityPolicy,omitempty"`
}

type SecurityPolicy struct {
	Type     string `json:"type,omitempty"`
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type Affected struct {
	Resource       ResourceRef          `json:"resource"`
	Exposure       *Exposure            `json:"exposure,omitempty"`
	Classification *AssetClassification `json:"classification,omitempty"`
	Pain           *Pain                `json:"pain,omitempty"`
	Remediation    *Remediation         `json:"remediation,omitempty"`
}

type AssetClassification struct {
	Class                             string `json:"class,omitempty"`
	ClassSource                       string `json:"classSource,omitempty"`
	SecurityImpactProfile             string `json:"securityImpactProfile,omitempty"`
	SecurityImpactProfileSource       string `json:"securityImpactProfileSource,omitempty"`
	SecurityImpactProfileRequirements string `json:"securityImpactProfileRequirements,omitempty"`
	SecurityRequirementsCeiling       string `json:"securityRequirementsCeiling,omitempty"`
	SecurityRequirementsCeilingSource string `json:"securityRequirementsCeilingSource,omitempty"`
	Recalculated                      bool   `json:"recalculated,omitempty"`
}

// Remediation is the FedRAMP Rev5 VDR-TFR-PVR remediation deadline for a finding
// on an asset, selected by the provider Certification Class, the PAIN rating, and
// the exploitability column (LEV+IRV | LEV+NIRV | NLEV).
type Remediation struct {
	Class string `json:"class"` // A|B|C|D
	// ClassSource records which signal set Class: label | namespaceLabel |
	// configMap | scoringConfig | builtin. "configMap" means the in-cluster
	// vdr-fedramp ConfigMap class applied because no label was present;
	// "scoringConfig" means a --scoring-config file set it; "builtin" means
	// nothing was configured anywhere and the built-in Class B applied.
	ClassSource  string  `json:"classSource,omitempty"`
	Column       string  `json:"column"`       // LEV+IRV|LEV+NIRV|NLEV
	LEV          bool    `json:"lev"`          // likely exploitable
	IRV          bool    `json:"irv"`          // internet reachable
	DeadlineDays float64 `json:"deadlineDays"` // < 0 => no FedRAMP deadline (PAIN-1)
	Deadline     string  `json:"deadline"`     // human-readable (e.g. "12 hours")
}

// Pain is the FedRAMP Rev5 VDR Potential Agency Impact rating (N1-N5) for a
// finding on a specific asset. Tier is derived from the CVSS impact vector
// weighted by the asset security-impact profile's CR/IR/AR requirements and the agency scope.
type Pain struct {
	Tier                              string  `json:"tier"`                        // N1..N5
	Word                              string  `json:"word"`                        // Minimal|Narrow|Disruptive|Debilitating
	Severity                          float64 `json:"severity"`                    // normalized environmental impact scalar 0..1
	SecurityImpactProfile             string  `json:"securityImpactProfile"`       // direct vector, decision trace, or named archetype
	SecurityImpactProfileSource       string  `json:"securityImpactProfileSource"` // label|namespaceLabel|nameRule|kindRule|namespaceRule|default|failsafe
	SecurityImpactProfileRequirements string  `json:"securityImpactProfileRequirements,omitempty"`
	SecurityRequirementsCeiling       string  `json:"securityRequirementsCeiling,omitempty"`
	SecurityRequirementsCeilingSource string  `json:"securityRequirementsCeilingSource,omitempty"`
	Recalculated                      bool    `json:"recalculated,omitempty"`
	SeveritySource                    string  `json:"severitySource,omitempty"` // technicalImpact|cvss|severity
	CR                                string  `json:"cr"`                       // effective confidentiality requirement (L|M|H)
	IR                                string  `json:"ir"`                       // effective integrity requirement (L|M|H)
	AR                                string  `json:"ar"`                       // effective availability requirement (L|M|H)
	MultiAgency                       bool    `json:"multiAgency"`              // effective scope used (incl. fail-safe)
	// MultiAgencySource records which signal set MultiAgency: label |
	// namespaceLabel | multiAgencyNamespaces | configMap | scoringConfig |
	// builtin | failsafe. "configMap" means the in-cluster vdr-fedramp ConfigMap
	// value applied because no label or namespace glob matched; "builtin" means
	// nothing was configured anywhere.
	MultiAgencySource string `json:"multiAgencySource,omitempty"`
}

type Report struct {
	ReportSchemaVersion string                `json:"reportSchemaVersion"`
	GeneratedAt         time.Time             `json:"generatedAt"`
	ScannerVersion      string                `json:"scannerVersion"`
	PluginVersion       string                `json:"pluginVersion"`
	ChainCatalog        *ChainCatalogMetadata `json:"chainCatalog,omitempty"`
	// ContextName is the Kubernetes context (kubectx) the inventory was collected
	// from. Shown in the report header.
	ContextName string `json:"contextName,omitempty"`
	// Class is the cluster-wide FedRAMP Certification Class (A/B/C/D) in effect for
	// scoring. Shown in the report header.
	Class    string    `json:"class,omitempty"`
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings,omitempty"`
	// CAPECTransitions contains exact same-resource CVE/CAPEC/CAPEC/CVE
	// candidate pairs derived from explicit CAPEC CanPrecede edges.
	CAPECTransitions []CAPECTransitionCandidate `json:"capecTransitions,omitempty"`
	// SuppressedFindings contains VEX/dispositioned findings kept for audit
	// visibility. These do not contribute to Summary.Findings or active
	// remediation calculations.
	SuppressedFindings []Finding        `json:"suppressedFindings,omitempty"`
	Resources          []ResourceReport `json:"resources,omitempty"`
	// Assets carries per-workload facts for the findings view, where nothing else
	// can attribute exposure to an individual workload: a Finding's own
	// `exposure` is a bestExposure roll-up across every asset the finding
	// touches, and an Affected entry only carries `exposure` when that workload
	// was individually assessed.
	//
	// Deliberately a separate field from Resources rather than a findings-less
	// Resources: the CycloneDX writer treats a non-empty Resources as "the
	// asset-centric view, read vulnerabilities from res.Findings" and skips its
	// findings-view fallback on that basis, so populating Resources here would
	// silently emit a VEX document containing zero vulnerabilities.
	Assets             []AssetFacts `json:"assets,omitempty"`
	Warnings           []string     `json:"warnings,omitempty"`
	ClassificationOnly bool         `json:"-"`
}

// AssetFacts is the per-workload projection of a ResourceReport: everything that
// describes the asset itself, with none of its findings. It exists so the
// findings view can publish authoritative per-asset exposure without duplicating
// the entire findings payload into a second asset-centric section.
type AssetFacts struct {
	Resource       ResourceRef          `json:"resource"`
	Images         []ContainerImage     `json:"images,omitempty"`
	Exposure       *Exposure            `json:"exposure,omitempty"`
	Runtime        *RuntimeMetadata     `json:"runtime,omitempty"`
	Classification *AssetClassification `json:"classification,omitempty"`
	Labels         map[string]string    `json:"labels,omitempty"`
	Posture        *WorkloadPosture     `json:"posture,omitempty"`
}

type ResourceReport struct {
	Resource         ResourceRef          `json:"resource"`
	Images           []ContainerImage     `json:"images,omitempty"`
	Exposure         *Exposure            `json:"exposure,omitempty"`
	Runtime          *RuntimeMetadata     `json:"runtime,omitempty"`
	ProviderMetadata map[string]string    `json:"providerMetadata,omitempty"`
	Classification   *AssetClassification `json:"classification,omitempty"`
	Findings         []Finding            `json:"findings"`
	Labels           map[string]string    `json:"labels,omitempty"`
	// Posture holds neutral Kubernetes security-posture facts observed for this
	// workload (see WorkloadPosture), captured read-only for a downstream evaluator.
	Posture *WorkloadPosture `json:"posture,omitempty"`
}

type Summary struct {
	Contexts   int `json:"contexts,omitempty"`
	Namespaces int `json:"namespaces,omitempty"`
	Resources  int `json:"resources"`
	Images     int `json:"images"`
	Findings   int `json:"findings"`
	// FindingsWithSpecificCWE is the number of active findings that carry at least
	// one specific CWE. Paired with Findings it is the data-quality metric that
	// gates real-world PAIN Relief coverage.
	FindingsWithSpecificCWE int                   `json:"findingsWithSpecificCwe"`
	ChainTaxonomy           *ChainTaxonomySummary `json:"chainTaxonomy,omitempty"`
	BySeverity              map[string]int        `json:"bySeverity,omitempty"`
	InternetAccessible      int                   `json:"internetAccessible,omitempty"`
	// ImageScans reports how many of the inventory's images Trivy successfully
	// scanned, for every scan type (k8s, ECS, Cloud Run, Helm, standalone images).
	ImageScans *ImageScanSummary `json:"imageScans,omitempty"`
}

// ImageScanSummary reports the outcome of scanning the inventory's images with
// Trivy: how many succeeded, how many failed, and which images failed.
type ImageScanSummary struct {
	Total            int      `json:"total"`
	Succeeded        int      `json:"succeeded"`
	Failed           int      `json:"failed"`
	SucceededPercent float64  `json:"succeededPercent"`
	FailedImages     []string `json:"failedImages,omitempty"`
}

// ChainTaxonomySummary reports coverage of the offline taxonomy projection over
// active, post-filter findings. Counts are informational and do not affect any
// scoring result.
type ChainTaxonomySummary struct {
	MappedFindings                  int `json:"mappedFindings"`
	UnknownFindings                 int `json:"unknownFindings"`
	AmbiguousFindings               int `json:"ambiguousFindings"`
	FindingsWithATTACKTechnique     int `json:"findingsWithAttackTechnique"`
	FindingsWithExplicitPredecessor int `json:"findingsWithExplicitPredecessor"`
	FindingsWithExplicitSuccessor   int `json:"findingsWithExplicitSuccessor"`
	TransitionCandidates            int `json:"transitionCandidates"`
	EntrypointCandidates            int `json:"entrypointCandidates"`
	UniqueEntrypointCVEs            int `json:"uniqueEntrypointCves"`
	ResourcesWithTransitions        int `json:"resourcesWithTransitions"`
}
