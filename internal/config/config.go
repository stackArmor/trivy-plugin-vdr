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

	FormatJSON  = "json"
	FormatTable = "table"

	ViewFindings  = "findings"
	ViewResources = "resources"

	CacheCleanupAuto   = "auto"
	CacheCleanupAlways = "always"
	CacheCleanupNever  = "never"
)

var namespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type Config struct {
	Source                string
	ImageRefs             []string
	Project               string
	Regions               []string
	Namespaces            []string
	AllNamespaces         bool
	IncludeZeroDaemonSets bool
	Format                string
	View                  string
	Output                string
	CacheDir              string
	Timeout               time.Duration
	ImageSrc              string
	ParallelScans         int
	CacheCleanup          string
	CacheMinFreeGB        int
	CacheMinFreePercent   int
	HTMLOutput            string
	HTMLTemplate          string
	ScoringConfig         string
	MinSeverity           string
	MinEPSS               float64
	SkipEnrichment        bool
	RefreshEnrichment     bool
	SkipExposure          bool
	ReachabilityOnly      bool
	ScanReachabilityOnly  bool
	SkipRegistryAuth      bool
	NoGcloudAuth          bool
	NoECRAuth             bool
	VEXOCIRegistries      []string
	Quiet                 bool
	Debug                 bool
}

type namespaceList []string

func (n *namespaceList) String() string {
	return fmt.Sprint([]string(*n))
}

func (n *namespaceList) Set(value string) error {
	if value == "" {
		return errors.New("namespace cannot be empty")
	}
	if len(value) > 63 {
		return fmt.Errorf("invalid namespace %q: must be 63 characters or fewer", value)
	}
	if !namespacePattern.MatchString(value) {
		return fmt.Errorf("invalid namespace %q", value)
	}
	*n = append(*n, value)
	return nil
}

type regionList []string

func (r *regionList) String() string {
	return fmt.Sprint([]string(*r))
}

func (r *regionList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("region cannot be empty")
	}
	*r = append(*r, value)
	return nil
}

type commaList []string

func (c *commaList) String() string {
	return strings.Join([]string(*c), ",")
}

func (c *commaList) Set(value string) error {
	var values []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	*c = values
	return nil
}

func Parse(args []string) (Config, error) {
	return ParseWithOutput(args, io.Discard)
}

func ParseWithOutput(args []string, output io.Writer) (Config, error) {
	cfg := Default()
	namespaces := namespaceList(cfg.Namespaces)
	regions := regionList(cfg.Regions)
	timeout := cfg.Timeout.String()
	minEPSS := strconv.FormatFloat(cfg.MinEPSS, 'f', -1, 64)

	fs := flag.NewFlagSet("vdr", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: vdr <source> [flags]\n       vdr image [flags] IMAGE...\n\nSources:\n  k8s\n  cloudrun\n  ecs (not implemented yet)\n  image\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.StringVar(&cfg.Project, "project", cfg.Project, "Google Cloud project for cloudrun source")
	fs.Var(&regions, "region", "Google Cloud region for cloudrun source; may be repeated")
	fs.Var(&namespaces, "namespace", "Kubernetes namespace to scan; may be repeated")
	fs.BoolVar(&cfg.AllNamespaces, "all-namespaces", cfg.AllNamespaces, "scan all namespaces")
	fs.BoolVar(&cfg.IncludeZeroDaemonSets, "include-zero-daemonsets", cfg.IncludeZeroDaemonSets, "include DaemonSets with zero desired pods")
	fs.StringVar(&cfg.Format, "format", cfg.Format, "output format: json or table")
	fs.StringVar(&cfg.View, "view", cfg.View, "report view: findings or resources")
	fs.StringVar(&cfg.Output, "output", cfg.Output, "write output to file")
	fs.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "cache directory")
	fs.StringVar(&timeout, "timeout", timeout, "scan timeout")
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
	fs.Var((*commaList)(&cfg.VEXOCIRegistries), "vex-oci-registries", "comma-separated registry hosts or repository prefixes that may use OCI VEX attestations")
	fs.BoolVar(&cfg.Quiet, "quiet", cfg.Quiet, "suppress progress logging (warnings and errors only)")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable debug logging")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	source := fs.Arg(0)
	cfg.Source = source
	if source == "" {
		return Config{}, errors.New("source is required; expected one of: k8s, cloudrun, ecs, image")
	}
	if source == SourceECS {
		return Config{}, fmt.Errorf("source %q is not implemented yet", source)
	}
	if source != SourceK8s && source != SourceCloudRun && source != SourceImage {
		return Config{}, fmt.Errorf("unknown source %q; expected one of: k8s, cloudrun, ecs, image", source)
	}

	flagArgs := fs.Args()[1:]
	if err := fs.Parse(flagArgs); err != nil {
		return Config{}, err
	}
	if cfg.Source == SourceImage {
		cfg.ImageRefs = append([]string(nil), fs.Args()...)
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
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "all-namespaces":
			allNamespacesSet = true
		case "namespace":
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
	if cfg.ReachabilityOnly {
		if cfg.ScanReachabilityOnly {
			return Config{}, errors.New("--reachability-only cannot be used with --scan-reachability-only")
		}
		if cfg.SkipExposure {
			return Config{}, errors.New("--reachability-only cannot be used with --skip-exposure")
		}
		if cfg.Source == SourceImage {
			return Config{}, errors.New("--reachability-only is only valid for sources k8s and cloudrun, not image")
		}
		cfg.View = ViewResources
	}
	if cfg.ScanReachabilityOnly {
		if cfg.SkipExposure {
			return Config{}, errors.New("--scan-reachability-only cannot be used with --skip-exposure")
		}
		if cfg.Source == SourceImage {
			return Config{}, errors.New("--scan-reachability-only is only valid for sources k8s and cloudrun, not image")
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
			return Config{}, errors.New("--region is only valid for source cloudrun")
		}
		if len(cfg.ImageRefs) == 0 {
			return Config{}, errors.New("at least one image reference is required for source image")
		}
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
	case FormatJSON, FormatTable:
		return nil
	default:
		return fmt.Errorf("invalid format %q: must be json or table", value)
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
