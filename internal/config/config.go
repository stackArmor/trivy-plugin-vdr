package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SourceK8s      = "k8s"
	SourceCloudRun = "cloudrun"
	SourceECS      = "ecs"
	SourceImage    = "image"
	SourceHelm     = "helm"

	FormatJSON      = "json"
	FormatTable     = "table"
	FormatCycloneDX = "cyclonedx"

	ViewFindings  = "findings"
	ViewResources = "resources"

	CacheCleanupAuto   = "auto"
	CacheCleanupAlways = "always"
	CacheCleanupNever  = "never"
)

var namespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type Config struct {
	Source                       string
	ImageRefs                    []string
	Chart                        string
	ChartVersion                 string
	ChartRepo                    string
	ValuesFiles                  []string
	ReleaseName                  string
	IngressChart                 string
	IngressChartVersion          string
	IngressChartRepo             string
	IngressValuesFiles           []string
	IngressReleaseName           string
	IngressNamespace             string
	ConfigMap                    string
	KubeVersion                  string
	APIVersions                  []string
	IncludeCRDs                  bool
	Project                      string
	Regions                      []string
	Namespaces                   []string
	AllNamespaces                bool
	IncludeZeroDaemonSets        bool
	Format                       string
	View                         string
	Output                       string
	CacheDir                     string
	Timeout                      time.Duration
	ImageSrc                     string
	ParallelScans                int
	CacheCleanup                 string
	CacheMinFreeGB               int
	CacheMinFreePercent          int
	HTMLOutput                   string
	HTMLTemplate                 string
	ScoringConfig                string
	MinSeverity                  string
	MinEPSS                      float64
	SkipEnrichment               bool
	RefreshEnrichment            bool
	SkipExposure                 bool
	ReachabilityOnly             bool
	ScanReachabilityOnly         bool
	SkipRegistryAuth             bool
	NoGcloudAuth                 bool
	NoECRAuth                    bool
	GCPImpersonateServiceAccount string
	AWSRoleARN                   string
	OCIVEXIncluded               bool
	VEXOCIRegistries             []string
	Quiet                        bool
	Debug                        bool
}

type namespaceList []string

func (n *namespaceList) String() string {
	return fmt.Sprint([]string(*n))
}

func (n *namespaceList) Set(value string) error {
	values := splitCommaValues(value)
	if len(values) == 0 {
		return errors.New("namespace cannot be empty")
	}
	for _, namespace := range values {
		if len(namespace) > 63 {
			return fmt.Errorf("invalid namespace %q: must be 63 characters or fewer", namespace)
		}
		if !namespacePattern.MatchString(namespace) {
			return fmt.Errorf("invalid namespace %q", namespace)
		}
		*n = append(*n, namespace)
	}
	return nil
}

type regionList []string

func (r *regionList) String() string {
	return fmt.Sprint([]string(*r))
}

func (r *regionList) Set(value string) error {
	values := splitCommaValues(value)
	if len(values) == 0 {
		return errors.New("region cannot be empty")
	}
	*r = append(*r, values...)
	return nil
}

type commaList []string

func (c *commaList) String() string {
	return strings.Join([]string(*c), ",")
}

func (c *commaList) Set(value string) error {
	*c = splitCommaValues(value)
	return nil
}

// orderedList preserves repeated flag values exactly as they appeared. Helm
// applies values files from left to right, with the rightmost file taking
// precedence, so these entries must never be sorted or de-duplicated.
type orderedList []string

func (o *orderedList) String() string {
	return fmt.Sprint([]string(*o))
}

func (o *orderedList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value cannot be empty")
	}
	*o = append(*o, value)
	return nil
}

func splitCommaValues(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	return values
}

func Parse(args []string) (Config, error) {
	return ParseWithOutput(args, io.Discard)
}

func ParseWithOutput(args []string, output io.Writer) (Config, error) {
	cfg := Default()
	namespaces := namespaceList(cfg.Namespaces)
	regions := regionList(cfg.Regions)
	valuesFiles := orderedList(cfg.ValuesFiles)
	ingressValuesFiles := orderedList(cfg.IngressValuesFiles)
	apiVersions := orderedList(cfg.APIVersions)
	timeout := cfg.Timeout.String()
	minEPSS := strconv.FormatFloat(cfg.MinEPSS, 'f', -1, 64)

	fs := flag.NewFlagSet("vdr", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: vdr <source> [flags]\n       vdr image [flags] IMAGE...\n       vdr helm CHART [flags]\n\nSources:\n  k8s\n  cloudrun\n  ecs\n  image\n  helm\n\nCommon aliases:\n  -n, --namespace\n  -o, --output\n  -f, --format (-f means --values for the helm source)\n  -q, --quiet\n  -t, --timeout\n  -O, --oci-vex-included\n\nExamples:\n  vdr k8s -n default -f table\n  vdr k8s --namespace prod,dev --output vdr-k8s.json\n  vdr cloudrun --project my-gcp-project --region us-east4\n  vdr ecs --region us-gov-west-1\n  vdr image -O nginx:1.25\n  vdr helm ./chart -f values.yaml --format json\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.StringVar(&cfg.Project, "project", cfg.Project, "Google Cloud project for cloudrun source")
	fs.Var(&regions, "region", "cloud region for cloudrun or ecs source; may be repeated")
	fs.Var(&namespaces, "namespace", "Kubernetes namespace to scan; may be repeated")
	fs.Var(&namespaces, "n", "alias for --namespace")
	fs.BoolVar(&cfg.AllNamespaces, "all-namespaces", cfg.AllNamespaces, "scan all namespaces")
	fs.BoolVar(&cfg.IncludeZeroDaemonSets, "include-zero-daemonsets", cfg.IncludeZeroDaemonSets, "include DaemonSets with zero desired pods")
	fs.StringVar(&cfg.Format, "format", cfg.Format, "output format: json, table, or cyclonedx")
	fs.StringVar(&cfg.Format, "f", cfg.Format, "alias for --format")
	fs.StringVar(&cfg.View, "view", cfg.View, "report view: findings or resources")
	fs.StringVar(&cfg.Output, "output", cfg.Output, "write output to file")
	fs.StringVar(&cfg.Output, "o", cfg.Output, "alias for --output")
	fs.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "cache directory")
	fs.StringVar(&timeout, "timeout", timeout, "scan timeout")
	fs.StringVar(&timeout, "t", timeout, "alias for --timeout")
	fs.StringVar(&cfg.ImageSrc, "image-src", cfg.ImageSrc, "Trivy image source")
	fs.IntVar(&cfg.ParallelScans, "parallel-scans", cfg.ParallelScans, "maximum concurrent image scans")
	fs.StringVar(&cfg.CacheCleanup, "cache-cleanup", cfg.CacheCleanup, "Trivy scan cache cleanup policy: auto, always, or never")
	fs.IntVar(&cfg.CacheMinFreeGB, "cache-min-free-gb", cfg.CacheMinFreeGB, "minimum free disk space in GB before auto cache cleanup")
	fs.IntVar(&cfg.CacheMinFreePercent, "cache-min-free-percent", cfg.CacheMinFreePercent, "minimum free disk percentage before auto cache cleanup")
	fs.StringVar(&cfg.HTMLOutput, "html-output", cfg.HTMLOutput, "write optional standalone HTML report to file")
	fs.StringVar(&cfg.HTMLTemplate, "html-template", cfg.HTMLTemplate, "custom HTML report template path")
	fs.StringVar(&cfg.ScoringConfig, "scoring-config", cfg.ScoringConfig, "optional FedRAMP PAIN scoring config (YAML or JSON); built-in defaults are used when omitted")
	fs.StringVar(&cfg.MinSeverity, "min-severity", cfg.MinSeverity, "minimum severity")
	fs.StringVar(&minEPSS, "min-epss", minEPSS, "minimum EPSS score from 0 to 1")
	fs.BoolVar(&cfg.SkipEnrichment, "skip-enrichment", cfg.SkipEnrichment, "skip EPSS and Vulnrichment enrichment")
	fs.BoolVar(&cfg.RefreshEnrichment, "refresh-enrichment", cfg.RefreshEnrichment, "force EPSS and Vulnrichment enrichment refresh")
	fs.BoolVar(&cfg.SkipExposure, "skip-exposure", cfg.SkipExposure, "skip exposure analysis")
	fs.BoolVar(&cfg.ReachabilityOnly, "reachability-only", cfg.ReachabilityOnly, "collect internet reachability metadata only and skip Trivy image scans")
	fs.BoolVar(&cfg.ScanReachabilityOnly, "scan-reachability-only", cfg.ScanReachabilityOnly, "scan images and include internet reachability plus asset classification, without EPSS, Vulnrichment, PAIN, or remediation scoring output")
	fs.BoolVar(&cfg.SkipRegistryAuth, "skip-registry-auth", cfg.SkipRegistryAuth, "skip automatic private registry authentication")
	fs.BoolVar(&cfg.NoGcloudAuth, "no-gcloud-auth", cfg.NoGcloudAuth, "skip gcloud authentication for Google Artifact Registry/GCR images")
	fs.BoolVar(&cfg.NoECRAuth, "no-ecr-auth", cfg.NoECRAuth, "skip aws CLI authentication for ECR images")
	fs.StringVar(&cfg.GCPImpersonateServiceAccount, "gcp-impersonate-service-account", cfg.GCPImpersonateServiceAccount, "Google service account email to impersonate for Cloud Run metadata and GAR/GCR auth")
	fs.StringVar(&cfg.AWSRoleARN, "aws-role-arn", cfg.AWSRoleARN, "AWS role ARN to assume for ECR auth")
	fs.BoolVar(&cfg.OCIVEXIncluded, "oci-vex-included", cfg.OCIVEXIncluded, "include OCI VEX attestations from image registries")
	fs.BoolVar(&cfg.OCIVEXIncluded, "O", cfg.OCIVEXIncluded, "alias for --oci-vex-included")
	fs.Var((*commaList)(&cfg.VEXOCIRegistries), "vex-oci-registries", "comma-separated registry hosts or repository prefixes that may use OCI VEX attestations")
	fs.BoolVar(&cfg.Quiet, "quiet", cfg.Quiet, "suppress progress logging (warnings and errors only)")
	fs.BoolVar(&cfg.Quiet, "q", cfg.Quiet, "alias for --quiet")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable debug logging")
	fs.Var(&valuesFiles, "values", "Helm values file for the application chart; may be repeated, rightmost file wins")
	fs.StringVar(&cfg.ReleaseName, "release-name", cfg.ReleaseName, "Helm release name used to render the application chart")
	fs.StringVar(&cfg.ChartVersion, "chart-version", cfg.ChartVersion, "version constraint for a remote Helm chart")
	fs.StringVar(&cfg.ChartRepo, "repo", cfg.ChartRepo, "Helm chart repository URL for an unqualified remote chart")
	fs.StringVar(&cfg.IngressChart, "ingress-chart", cfg.IngressChart, "additional Helm chart containing Ingress, ingress-controller, or Gateway API infrastructure")
	fs.StringVar(&cfg.IngressChartVersion, "ingress-chart-version", cfg.IngressChartVersion, "version constraint for the remote --ingress-chart")
	fs.StringVar(&cfg.IngressChartRepo, "ingress-repo", cfg.IngressChartRepo, "Helm chart repository URL for an unqualified remote --ingress-chart")
	fs.Var(&ingressValuesFiles, "ingress-values", "Helm values file for --ingress-chart; may be repeated, rightmost file wins")
	fs.StringVar(&cfg.IngressReleaseName, "ingress-release-name", cfg.IngressReleaseName, "Helm release name used to render --ingress-chart")
	fs.StringVar(&cfg.IngressNamespace, "ingress-namespace", cfg.IngressNamespace, "namespace used to render --ingress-chart; defaults to --namespace")
	fs.StringVar(&cfg.ConfigMap, "config-map", cfg.ConfigMap, "VDR scoring ConfigMap manifest to consume with a Helm chart")
	fs.StringVar(&cfg.KubeVersion, "kube-version", cfg.KubeVersion, "Kubernetes version used for Helm template capabilities")
	fs.Var(&apiVersions, "api-versions", "Kubernetes API version available to Helm templates; may be repeated")
	fs.BoolVar(&cfg.IncludeCRDs, "include-crds", cfg.IncludeCRDs, "include CRDs in Helm rendered output")

	if err := fs.Parse(args); err != nil {
		return Config{}, suggestFlagError(err)
	}
	source := fs.Arg(0)
	cfg.Source = source
	if source == "" {
		return Config{}, errors.New("source is required; expected one of: k8s, cloudrun, ecs, image, helm")
	}
	if source != SourceK8s && source != SourceCloudRun && source != SourceECS && source != SourceImage && source != SourceHelm {
		return Config{}, fmt.Errorf("unknown source %q; expected one of: k8s, cloudrun, ecs, image, helm", source)
	}

	flagArgs := fs.Args()[1:]
	if source == SourceHelm {
		configureHelmHelp(fs)
		flagArgs = helmFlagArgs(fs, flagArgs)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return Config{}, suggestFlagError(err)
	}
	if cfg.Source == SourceImage {
		cfg.ImageRefs = append([]string(nil), fs.Args()...)
	} else if cfg.Source == SourceHelm {
		if fs.NArg() != 1 {
			if fs.NArg() == 0 {
				return Config{}, errors.New("chart path is required for source helm")
			}
			return Config{}, fmt.Errorf("unexpected argument %q for source %q", fs.Arg(1), source)
		}
		cfg.Chart = fs.Arg(0)
	} else if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected argument %q for source %q", fs.Arg(0), source)
	}
	allNamespacesSet := false
	namespaceSet := false
	includeZeroDaemonSetsSet := false
	projectSet := false
	regionSet := false
	htmlOutputSet := false
	htmlTemplateSet := false
	minEPSSSet := false
	helmSpecificFlag := ""
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "all-namespaces":
			allNamespacesSet = true
		case "namespace", "n":
			namespaceSet = true
		case "include-zero-daemonsets":
			includeZeroDaemonSetsSet = true
		case "project":
			projectSet = true
		case "region":
			regionSet = true
		case "html-output":
			htmlOutputSet = true
		case "html-template":
			htmlTemplateSet = true
		case "min-epss":
			minEPSSSet = true
		case "values", "release-name", "chart-version", "repo", "ingress-chart", "ingress-chart-version", "ingress-repo", "ingress-values", "ingress-release-name", "ingress-namespace", "config-map", "kube-version", "api-versions", "include-crds":
			helmSpecificFlag = f.Name
		}
	})

	parsedTimeout, err := time.ParseDuration(timeout)
	if err != nil {
		return Config{}, fmt.Errorf("invalid timeout %q: %w", timeout, err)
	}
	if parsedTimeout <= 0 {
		return Config{}, fmt.Errorf("invalid timeout %q: must be greater than zero", timeout)
	}
	cfg.Timeout = parsedTimeout

	parsedEPSS, err := strconv.ParseFloat(minEPSS, 64)
	if err != nil {
		return Config{}, fmt.Errorf("invalid min-epss %q: %w", minEPSS, err)
	}
	if math.IsNaN(parsedEPSS) || math.IsInf(parsedEPSS, 0) || (parsedEPSS != -1 && (parsedEPSS < 0 || parsedEPSS > 1)) {
		return Config{}, fmt.Errorf("invalid min-epss %v: must be -1 or between 0 and 1", parsedEPSS)
	}
	cfg.MinEPSS = parsedEPSS
	cfg.Namespaces = []string(namespaces)
	cfg.Regions = []string(regions)
	cfg.ValuesFiles = []string(valuesFiles)
	cfg.IngressValuesFiles = []string(ingressValuesFiles)
	cfg.APIVersions = []string(apiVersions)
	cfg.Format = strings.ToLower(strings.TrimSpace(cfg.Format))
	cfg.View = strings.ToLower(strings.TrimSpace(cfg.View))
	cfg.CacheCleanup = strings.ToLower(strings.TrimSpace(cfg.CacheCleanup))
	cfg.MinSeverity = strings.ToUpper(strings.TrimSpace(cfg.MinSeverity))
	if cfg.ReachabilityOnly {
		if cfg.ScanReachabilityOnly {
			return Config{}, errors.New("--reachability-only cannot be used with --scan-reachability-only")
		}
		if cfg.SkipExposure {
			return Config{}, errors.New("--reachability-only cannot be used with --skip-exposure")
		}
		if cfg.Source == SourceImage {
			return Config{}, errors.New("--reachability-only is only valid for sources k8s, cloudrun, and ecs, not image")
		}
		cfg.View = ViewResources
	}
	if cfg.ScanReachabilityOnly {
		if cfg.SkipExposure {
			return Config{}, errors.New("--scan-reachability-only cannot be used with --skip-exposure")
		}
		if cfg.Source == SourceImage {
			return Config{}, errors.New("--scan-reachability-only is only valid for sources k8s, cloudrun, and ecs, not image")
		}
		if htmlOutputSet || cfg.HTMLOutput != "" {
			return Config{}, errors.New("--scan-reachability-only cannot be used with --html-output")
		}
		if htmlTemplateSet || cfg.HTMLTemplate != "" {
			return Config{}, errors.New("--scan-reachability-only cannot be used with --html-template")
		}
		if minEPSSSet {
			return Config{}, errors.New("--scan-reachability-only cannot be used with --min-epss")
		}
	}
	if cfg.Source == SourceCloudRun {
		if namespaceSet {
			return Config{}, errors.New("--namespace is only valid for source k8s")
		}
		if allNamespacesSet {
			return Config{}, errors.New("--all-namespaces is only valid for source k8s")
		}
		if includeZeroDaemonSetsSet {
			return Config{}, errors.New("--include-zero-daemonsets is only valid for source k8s")
		}
		if strings.TrimSpace(cfg.Project) == "" {
			return Config{}, errors.New("--project is required for source cloudrun")
		}
		if len(cfg.Regions) == 0 {
			return Config{}, errors.New("--region is required for source cloudrun")
		}
	}
	if cfg.Source == SourceECS {
		if namespaceSet {
			return Config{}, errors.New("--namespace is only valid for source k8s")
		}
		if allNamespacesSet {
			return Config{}, errors.New("--all-namespaces is only valid for source k8s")
		}
		if includeZeroDaemonSetsSet {
			return Config{}, errors.New("--include-zero-daemonsets is only valid for source k8s")
		}
		if projectSet || strings.TrimSpace(cfg.Project) != "" {
			return Config{}, errors.New("--project is only valid for source cloudrun")
		}
		if len(cfg.Regions) == 0 {
			return Config{}, errors.New("--region is required for source ecs")
		}
	}
	if cfg.Source == SourceImage {
		if namespaceSet {
			return Config{}, errors.New("--namespace is only valid for source k8s")
		}
		if allNamespacesSet {
			return Config{}, errors.New("--all-namespaces is only valid for source k8s")
		}
		if includeZeroDaemonSetsSet {
			return Config{}, errors.New("--include-zero-daemonsets is only valid for source k8s")
		}
		if projectSet || strings.TrimSpace(cfg.Project) != "" {
			return Config{}, errors.New("--project is only valid for source cloudrun")
		}
		if regionSet || len(cfg.Regions) > 0 {
			return Config{}, errors.New("--region is only valid for sources cloudrun and ecs")
		}
		if len(cfg.ImageRefs) == 0 {
			return Config{}, errors.New("at least one image reference is required for source image")
		}
	}
	if cfg.Source == SourceHelm {
		if allNamespacesSet {
			return Config{}, errors.New("--all-namespaces is only valid for source k8s")
		}
		if includeZeroDaemonSetsSet {
			return Config{}, errors.New("--include-zero-daemonsets is only valid for source k8s")
		}
		if projectSet || strings.TrimSpace(cfg.Project) != "" {
			return Config{}, errors.New("--project is only valid for source cloudrun")
		}
		if regionSet || len(cfg.Regions) > 0 {
			return Config{}, errors.New("--region is only valid for sources cloudrun and ecs")
		}
		if len(cfg.Namespaces) > 1 {
			return Config{}, errors.New("source helm accepts at most one --namespace")
		}
		if len(cfg.Namespaces) == 0 {
			cfg.Namespaces = []string{"default"}
		}
		cfg.AllNamespaces = false
		cfg.ReleaseName = strings.TrimSpace(cfg.ReleaseName)
		if cfg.ReleaseName == "" {
			cfg.ReleaseName = "vdr-scan"
		}
		cfg.IngressChart = strings.TrimSpace(cfg.IngressChart)
		if cfg.IngressChart == "" {
			if len(cfg.IngressValuesFiles) > 0 || cfg.IngressReleaseName != "" || cfg.IngressNamespace != "" || cfg.IngressChartVersion != "" || cfg.IngressChartRepo != "" {
				return Config{}, errors.New("--ingress-chart is required when ingress chart options are set")
			}
		} else {
			cfg.IngressReleaseName = strings.TrimSpace(cfg.IngressReleaseName)
			if cfg.IngressReleaseName == "" {
				cfg.IngressReleaseName = "vdr-edge"
			}
			cfg.IngressNamespace = strings.TrimSpace(cfg.IngressNamespace)
			if cfg.IngressNamespace == "" {
				cfg.IngressNamespace = cfg.Namespaces[0]
			}
			if len(cfg.IngressNamespace) > 63 || !namespacePattern.MatchString(cfg.IngressNamespace) {
				return Config{}, fmt.Errorf("invalid ingress namespace %q", cfg.IngressNamespace)
			}
		}
	} else if helmSpecificFlag != "" {
		return Config{}, fmt.Errorf("--%s is only valid for source helm", helmSpecificFlag)
	}
	if len(cfg.Namespaces) > 0 && allNamespacesSet && cfg.AllNamespaces {
		return Config{}, errors.New("cannot use --namespace with --all-namespaces")
	}
	if len(cfg.Namespaces) > 0 && !allNamespacesSet {
		cfg.AllNamespaces = false
	}

	if err := validateFormat(cfg.Format); err != nil {
		return Config{}, err
	}
	if err := validateView(cfg.View); err != nil {
		return Config{}, err
	}
	if err := validateSeverity(cfg.MinSeverity); err != nil {
		return Config{}, err
	}
	if cfg.ParallelScans <= 0 {
		return Config{}, fmt.Errorf("invalid parallel-scans %d: must be greater than zero", cfg.ParallelScans)
	}
	if err := validateCacheCleanup(cfg.CacheCleanup); err != nil {
		return Config{}, err
	}
	if cfg.CacheMinFreeGB < 0 {
		return Config{}, fmt.Errorf("invalid cache-min-free-gb %d: must be greater than or equal to zero", cfg.CacheMinFreeGB)
	}
	if cfg.CacheMinFreePercent < 0 || cfg.CacheMinFreePercent > 100 {
		return Config{}, fmt.Errorf("invalid cache-min-free-percent %d: must be between 0 and 100", cfg.CacheMinFreePercent)
	}

	return cfg, nil
}

func Default() Config {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return Config{
		AllNamespaces:         true,
		IncludeZeroDaemonSets: false,
		Format:                FormatJSON,
		View:                  ViewFindings,
		CacheDir:              filepath.Join(home, ".cache", "trivy", "vdr"),
		Timeout:               30 * time.Minute,
		ImageSrc:              "remote",
		ParallelScans:         5,
		CacheCleanup:          CacheCleanupAuto,
		CacheMinFreeGB:        10,
		CacheMinFreePercent:   10,
		MinEPSS:               -1,
	}
}

func validateFormat(value string) error {
	switch value {
	case FormatJSON, FormatTable, FormatCycloneDX:
		return nil
	default:
		return fmt.Errorf("invalid format %q: must be json, table, or cyclonedx", value)
	}
}

func validateView(value string) error {
	switch value {
	case ViewFindings, ViewResources:
		return nil
	default:
		return fmt.Errorf("invalid view %q: must be findings or resources", value)
	}
}

func validateSeverity(value string) error {
	switch value {
	case "", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return nil
	default:
		return fmt.Errorf("invalid min-severity %q", value)
	}
}

func validateCacheCleanup(value string) error {
	switch value {
	case CacheCleanupAuto, CacheCleanupAlways, CacheCleanupNever:
		return nil
	default:
		return fmt.Errorf("invalid cache-cleanup %q: must be auto, always, or never", value)
	}
}

func suggestFlagError(err error) error {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return err
	}
	const prefix = "flag provided but not defined: -"
	msg := err.Error()
	idx := strings.Index(msg, prefix)
	if idx == -1 {
		return err
	}
	name := strings.TrimSpace(msg[idx+len(prefix):])
	if name == "" {
		return err
	}
	name = strings.TrimLeft(name, "-")
	suggestions := map[string]string{
		"namespaces":      "--namespace",
		"ns":              "--namespace",
		"regions":         "--region",
		"projects":        "--project",
		"outputs":         "--output",
		"formats":         "--format",
		"oci-vex-include": "--oci-vex-included",
	}
	if suggestion, ok := suggestions[name]; ok {
		return fmt.Errorf("%w (unknown flag --%s); did you mean %s?", err, name, suggestion)
	}
	return err
}

// helmFlagArgs makes the Helm source behave like Helm's CLI while leaving the
// established parsers for other sources untouched. The standard library flag
// package stops at the first positional argument, but users naturally write
// `vdr helm CHART -f values.yaml`. Move flags ahead of the chart for parsing and
// reinterpret Helm's -f alias as --values. The relative order of repeated
// --values flags is preserved.
func helmFlagArgs(fs *flag.FlagSet, args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if arg == "-f" {
			arg = "--values"
		} else if strings.HasPrefix(arg, "-f=") {
			arg = "--values=" + strings.TrimPrefix(arg, "-f=")
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if before, _, ok := strings.Cut(name, "="); ok {
			name = before
		} else if f := fs.Lookup(name); f != nil && !isBoolFlag(f) && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}

func isBoolFlag(f *flag.Flag) bool {
	type boolFlag interface {
		IsBoolFlag() bool
	}
	v, ok := f.Value.(boolFlag)
	return ok && v.IsBoolFlag()
}

func configureHelmHelp(fs *flag.FlagSet) {
	if f := fs.Lookup("f"); f != nil {
		f.Usage = "alias for --values for the Helm source; may be repeated, rightmost file wins"
		f.DefValue = ""
	}
	if f := fs.Lookup("namespace"); f != nil {
		f.Usage = "namespace used to render Helm charts and default namespaced manifests"
	}
	if f := fs.Lookup("n"); f != nil {
		f.Usage = "alias for --namespace"
	}
}
