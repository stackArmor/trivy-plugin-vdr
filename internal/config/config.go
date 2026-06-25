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
	"time"
)

const (
	SourceK8s   = "k8s"
	SourceECS   = "ecs"
	SourceImage = "image"

	FormatJSON  = "json"
	FormatTable = "table"

	ViewFindings  = "findings"
	ViewResources = "resources"
)

var namespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type Config struct {
	Source                string
	Namespaces            []string
	AllNamespaces         bool
	IncludeZeroDaemonSets bool
	Format                string
	View                  string
	Output                string
	CacheDir              string
	Timeout               time.Duration
	MinSeverity           string
	MinEPSS               float64
	SkipEnrichment        bool
	SkipExposure          bool
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

func Parse(args []string) (Config, error) {
	return ParseWithOutput(args, io.Discard)
}

func ParseWithOutput(args []string, output io.Writer) (Config, error) {
	cfg := Default()
	namespaces := namespaceList(cfg.Namespaces)
	timeout := cfg.Timeout.String()
	minEPSS := strconv.FormatFloat(cfg.MinEPSS, 'f', -1, 64)

	fs := flag.NewFlagSet("vdr", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: vdr <source> [flags]\n\nSources:\n  k8s\n  ecs (not implemented yet)\n  image (not implemented yet)\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Var(&namespaces, "namespace", "Kubernetes namespace to scan; may be repeated")
	fs.BoolVar(&cfg.AllNamespaces, "all-namespaces", cfg.AllNamespaces, "scan all namespaces")
	fs.BoolVar(&cfg.IncludeZeroDaemonSets, "include-zero-daemonsets", cfg.IncludeZeroDaemonSets, "include DaemonSets with zero desired pods")
	fs.StringVar(&cfg.Format, "format", cfg.Format, "output format: json or table")
	fs.StringVar(&cfg.View, "view", cfg.View, "report view: findings or resources")
	fs.StringVar(&cfg.Output, "output", cfg.Output, "write output to file")
	fs.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "cache directory")
	fs.StringVar(&timeout, "timeout", timeout, "scan timeout")
	fs.StringVar(&cfg.MinSeverity, "min-severity", cfg.MinSeverity, "minimum severity")
	fs.StringVar(&minEPSS, "min-epss", minEPSS, "minimum EPSS score from 0 to 1")
	fs.BoolVar(&cfg.SkipEnrichment, "skip-enrichment", cfg.SkipEnrichment, "skip EPSS and Vulnrichment enrichment")
	fs.BoolVar(&cfg.SkipExposure, "skip-exposure", cfg.SkipExposure, "skip exposure analysis")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable debug logging")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	source := fs.Arg(0)
	cfg.Source = source
	if source == "" {
		return Config{}, errors.New("source is required; expected one of: k8s, ecs, image")
	}
	if source == SourceECS || source == SourceImage {
		return Config{}, fmt.Errorf("source %q is not implemented yet", source)
	}
	if source != SourceK8s {
		return Config{}, fmt.Errorf("unknown source %q; expected one of: k8s, ecs, image", source)
	}

	flagArgs := fs.Args()[1:]
	if err := fs.Parse(flagArgs); err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected argument %q for source %q", fs.Arg(0), source)
	}
	allNamespacesSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "all-namespaces" {
			allNamespacesSet = true
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
