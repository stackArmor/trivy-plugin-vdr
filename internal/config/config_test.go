package config

import (
	"errors"
	"flag"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg, err := Parse([]string{"k8s"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	wantCacheDir := filepath.Join(home, ".cache", "trivy", "vdr")
	if cfg.Source != "k8s" {
		t.Fatalf("Source = %q, want k8s", cfg.Source)
	}
	if cfg.AllNamespaces != true {
		t.Fatalf("AllNamespaces = %v, want true", cfg.AllNamespaces)
	}
	if cfg.IncludeZeroDaemonSets != false {
		t.Fatalf("IncludeZeroDaemonSets = %v, want false", cfg.IncludeZeroDaemonSets)
	}
	if cfg.Format != "json" {
		t.Fatalf("Format = %q, want json", cfg.Format)
	}
	if cfg.View != "findings" {
		t.Fatalf("View = %q, want findings", cfg.View)
	}
	if cfg.CacheDir != wantCacheDir {
		t.Fatalf("CacheDir = %q, want %q", cfg.CacheDir, wantCacheDir)
	}
	if cfg.Timeout != 30*time.Minute {
		t.Fatalf("Timeout = %v, want 30m", cfg.Timeout)
	}
	if cfg.MinSeverity != "" {
		t.Fatalf("MinSeverity = %q, want empty", cfg.MinSeverity)
	}
	if cfg.MinEPSS != -1 {
		t.Fatalf("MinEPSS = %v, want -1", cfg.MinEPSS)
	}
	if cfg.ImageSrc != "remote" {
		t.Fatalf("ImageSrc = %q, want remote", cfg.ImageSrc)
	}
	if cfg.ParallelScans != 5 {
		t.Fatalf("ParallelScans = %d, want 5", cfg.ParallelScans)
	}
	if cfg.CacheCleanup != "auto" {
		t.Fatalf("CacheCleanup = %q, want auto", cfg.CacheCleanup)
	}
	if cfg.CacheMinFreeGB != 10 {
		t.Fatalf("CacheMinFreeGB = %d, want 10", cfg.CacheMinFreeGB)
	}
	if cfg.CacheMinFreePercent != 10 {
		t.Fatalf("CacheMinFreePercent = %d, want 10", cfg.CacheMinFreePercent)
	}
	if cfg.HTMLOutput != "" || cfg.HTMLTemplate != "" {
		t.Fatalf("HTMLOutput/HTMLTemplate = %q/%q, want empty", cfg.HTMLOutput, cfg.HTMLTemplate)
	}
	if cfg.SkipEnrichment || cfg.RefreshEnrichment || cfg.SkipExposure || cfg.Debug {
		t.Fatalf("SkipEnrichment/RefreshEnrichment/SkipExposure/Debug = %v/%v/%v/%v, want all false", cfg.SkipEnrichment, cfg.RefreshEnrichment, cfg.SkipExposure, cfg.Debug)
	}
	if cfg.SkipRegistryAuth || cfg.NoGcloudAuth || cfg.NoECRAuth || cfg.Quiet {
		t.Fatalf("registry auth/quiet flags = %v/%v/%v/%v, want all false", cfg.SkipRegistryAuth, cfg.NoGcloudAuth, cfg.NoECRAuth, cfg.Quiet)
	}
}

func TestParseRegistryAuthAndLogFlags(t *testing.T) {
	cfg, err := Parse([]string{
		"k8s",
		"--skip-registry-auth",
		"--no-gcloud-auth",
		"--no-ecr-auth",
		"--gcp-impersonate-service-account", "vdr-reader@example.iam.gserviceaccount.com",
		"--aws-role-arn", "arn:aws:iam::123456789012:role/VDRReadOnly",
		"--quiet",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !cfg.SkipRegistryAuth || !cfg.NoGcloudAuth || !cfg.NoECRAuth || !cfg.Quiet {
		t.Fatalf("flags = %v/%v/%v/%v, want all true", cfg.SkipRegistryAuth, cfg.NoGcloudAuth, cfg.NoECRAuth, cfg.Quiet)
	}
	if cfg.GCPImpersonateServiceAccount != "vdr-reader@example.iam.gserviceaccount.com" {
		t.Fatalf("GCPImpersonateServiceAccount = %q", cfg.GCPImpersonateServiceAccount)
	}
	if cfg.AWSRoleARN != "arn:aws:iam::123456789012:role/VDRReadOnly" {
		t.Fatalf("AWSRoleARN = %q", cfg.AWSRoleARN)
	}
}

func TestParseShortAliases(t *testing.T) {
	cfg, err := Parse([]string{
		"k8s",
		"-f", "table",
		"-o", "report.json",
		"-q",
		"-t", "45s",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Format != FormatTable {
		t.Fatalf("Format = %q, want %q", cfg.Format, FormatTable)
	}
	if cfg.Output != "report.json" {
		t.Fatalf("Output = %q, want report.json", cfg.Output)
	}
	if !cfg.Quiet {
		t.Fatal("Quiet = false, want true")
	}
	if cfg.Timeout != 45*time.Second {
		t.Fatalf("Timeout = %v, want 45s", cfg.Timeout)
	}
}

func TestParseVEXOCIRegistries(t *testing.T) {
	cfg, err := Parse([]string{
		"k8s",
		"--vex-oci-registries", "registry.example.com, ghcr.io/acme",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	want := []string{"registry.example.com", "ghcr.io/acme"}
	if !reflect.DeepEqual(cfg.VEXOCIRegistries, want) {
		t.Fatalf("VEXOCIRegistries = %#v, want %#v", cfg.VEXOCIRegistries, want)
	}
}

func TestParseOCIVEXIncludedAliases(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "long", args: []string{"k8s", "--oci-vex-included"}},
		{name: "short", args: []string{"k8s", "-O"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			if !cfg.OCIVEXIncluded {
				t.Fatal("OCIVEXIncluded = false, want true")
			}
		})
	}
}

func TestParseScanAndCacheFlags(t *testing.T) {
	cfg, err := Parse([]string{
		"k8s",
		"--image-src", "remote,local",
		"--parallel-scans", "3",
		"--cache-cleanup", "always",
		"--cache-min-free-gb", "0",
		"--cache-min-free-percent", "25",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if cfg.ImageSrc != "remote,local" {
		t.Fatalf("ImageSrc = %q, want remote,local", cfg.ImageSrc)
	}
	if cfg.ParallelScans != 3 {
		t.Fatalf("ParallelScans = %d, want 3", cfg.ParallelScans)
	}
	if cfg.CacheCleanup != "always" {
		t.Fatalf("CacheCleanup = %q, want always", cfg.CacheCleanup)
	}
	if cfg.CacheMinFreeGB != 0 {
		t.Fatalf("CacheMinFreeGB = %d, want 0", cfg.CacheMinFreeGB)
	}
	if cfg.CacheMinFreePercent != 25 {
		t.Fatalf("CacheMinFreePercent = %d, want 25", cfg.CacheMinFreePercent)
	}
}

func TestParseRefreshEnrichment(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--refresh-enrichment"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !cfg.RefreshEnrichment {
		t.Fatal("RefreshEnrichment = false, want true")
	}
}

func TestParseHTMLReportFlags(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--html-output", "report.html", "--html-template", "template.html"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.HTMLOutput != "report.html" {
		t.Fatalf("HTMLOutput = %q, want report.html", cfg.HTMLOutput)
	}
	if cfg.HTMLTemplate != "template.html" {
		t.Fatalf("HTMLTemplate = %q, want template.html", cfg.HTMLTemplate)
	}
}

func TestParseNamespaceFlags(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--namespace", "prod", "--namespace", "dev"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if cfg.AllNamespaces {
		t.Fatal("AllNamespaces = true, want false")
	}
	if !reflect.DeepEqual(cfg.Namespaces, []string{"prod", "dev"}) {
		t.Fatalf("Namespaces = %#v, want prod/dev", cfg.Namespaces)
	}
}

func TestParseNamespaceShortAlias(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "-n", "prod", "-n", "dev"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if cfg.AllNamespaces {
		t.Fatal("AllNamespaces = true, want false")
	}
	if !reflect.DeepEqual(cfg.Namespaces, []string{"prod", "dev"}) {
		t.Fatalf("Namespaces = %#v, want prod/dev", cfg.Namespaces)
	}
}

func TestParseNamespaceAcceptsCommaSeparatedValues(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--namespace", "prod, dev", "-n", "stage"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if cfg.AllNamespaces {
		t.Fatal("AllNamespaces = true, want false")
	}
	if !reflect.DeepEqual(cfg.Namespaces, []string{"prod", "dev", "stage"}) {
		t.Fatalf("Namespaces = %#v, want prod/dev/stage", cfg.Namespaces)
	}
}

func TestParseCloudRunSourceRequiresProjectAndRegion(t *testing.T) {
	_, err := Parse([]string{"cloudrun"})
	if err == nil || !strings.Contains(err.Error(), "--project") {
		t.Fatalf("error = %v, want missing project", err)
	}

	_, err = Parse([]string{"cloudrun", "--project", "armory-gss-prod"})
	if err == nil || !strings.Contains(err.Error(), "--region") {
		t.Fatalf("error = %v, want missing region", err)
	}
}

func TestParseCloudRunSource(t *testing.T) {
	cfg, err := Parse([]string{
		"cloudrun",
		"--project", "armory-gss-prod",
		"--region", "us-east4",
		"--region", "us-central1",
		"--view", "resources",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Source != SourceCloudRun {
		t.Fatalf("Source = %q, want %q", cfg.Source, SourceCloudRun)
	}
	if cfg.Project != "armory-gss-prod" {
		t.Fatalf("Project = %q", cfg.Project)
	}
	if !reflect.DeepEqual(cfg.Regions, []string{"us-east4", "us-central1"}) {
		t.Fatalf("Regions = %#v", cfg.Regions)
	}
	if cfg.View != "resources" {
		t.Fatalf("View = %q", cfg.View)
	}
}

func TestParseRegionAcceptsCommaSeparatedValues(t *testing.T) {
	cfg, err := Parse([]string{
		"cloudrun",
		"--project", "armory-gss-prod",
		"--region", "us-east4, us-central1",
		"--region", "us-west1",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !reflect.DeepEqual(cfg.Regions, []string{"us-east4", "us-central1", "us-west1"}) {
		t.Fatalf("Regions = %#v", cfg.Regions)
	}
}

func TestParseCloudRunRejectsKubernetesNamespaceFlags(t *testing.T) {
	_, err := Parse([]string{"cloudrun", "--project", "p", "--region", "us-east4", "--namespace", "default"})
	if err == nil || !strings.Contains(err.Error(), "--namespace") {
		t.Fatalf("error = %v, want namespace rejection", err)
	}
}

func TestParseECSSourceRequiresRegion(t *testing.T) {
	_, err := Parse([]string{"ecs"})
	if err == nil || !strings.Contains(err.Error(), "--region") {
		t.Fatalf("error = %v, want missing region", err)
	}
}

func TestParseECSSource(t *testing.T) {
	cfg, err := Parse([]string{
		"ecs",
		"--region", "us-gov-west-1",
		"--region", "us-east-1",
		"--view", "resources",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Source != SourceECS {
		t.Fatalf("Source = %q, want %q", cfg.Source, SourceECS)
	}
	if !reflect.DeepEqual(cfg.Regions, []string{"us-gov-west-1", "us-east-1"}) {
		t.Fatalf("Regions = %#v", cfg.Regions)
	}
	if cfg.View != "resources" {
		t.Fatalf("View = %q", cfg.View)
	}
}

func TestParseECSRejectsKubernetesAndCloudRunFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "namespace", args: []string{"ecs", "--region", "us-east-1", "--namespace", "default"}, want: "--namespace"},
		{name: "all namespaces", args: []string{"ecs", "--region", "us-east-1", "--all-namespaces"}, want: "--all-namespaces"},
		{name: "include zero daemonsets", args: []string{"ecs", "--region", "us-east-1", "--include-zero-daemonsets"}, want: "--include-zero-daemonsets"},
		{name: "project", args: []string{"ecs", "--region", "us-east-1", "--project", "p"}, want: "--project"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %s rejection", err, tt.want)
			}
		})
	}
}

func TestParseAllowsGlobalFlagsBeforeAndAfterK8sSource(t *testing.T) {
	cfg, err := Parse([]string{"--format", "table", "k8s", "--view", "resources", "--timeout", "45s"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if cfg.Source != "k8s" {
		t.Fatalf("Source = %q, want k8s", cfg.Source)
	}
	if cfg.Format != "table" {
		t.Fatalf("Format = %q, want table", cfg.Format)
	}
	if cfg.View != "resources" {
		t.Fatalf("View = %q, want resources", cfg.View)
	}
	if cfg.Timeout != 45*time.Second {
		t.Fatalf("Timeout = %v, want 45s", cfg.Timeout)
	}
}

func TestParseRequiresSource(t *testing.T) {
	_, err := Parse([]string{})
	if err == nil {
		t.Fatal("Parse returned nil error, want source required error")
	}
	if !strings.Contains(err.Error(), "source") {
		t.Fatalf("error = %q, want source context", err.Error())
	}
}

func TestParseShowsHelpAfterRootFlags(t *testing.T) {
	_, err := Parse([]string{"--debug", "--help"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Parse error = %v, want flag.ErrHelp", err)
	}
}

func TestParseRejectsExtraK8sPositionalArguments(t *testing.T) {
	_, err := Parse([]string{"k8s", "positional"})
	if err == nil {
		t.Fatal("Parse returned nil error, want unexpected positional argument error")
	}
	if !strings.Contains(err.Error(), "unexpected argument") || !strings.Contains(err.Error(), "positional") {
		t.Fatalf("error = %q, want unexpected argument context", err.Error())
	}
}

func TestParseUnknownRootFlagReportsFlagError(t *testing.T) {
	_, err := Parse([]string{"--unknown", "value", "k8s"})
	if err == nil {
		t.Fatal("Parse returned nil error, want unknown flag error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("error = %q, want unknown flag context", err.Error())
	}
	if strings.Contains(err.Error(), `unknown source "value"`) {
		t.Fatalf("error = %q, want flag error instead of source misclassification", err.Error())
	}
}

func TestParseUnknownFlagSuggestsKnownFlag(t *testing.T) {
	_, err := Parse([]string{"k8s", "--namespaces", "default"})
	if err == nil {
		t.Fatal("Parse returned nil error, want unknown flag error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") ||
		!strings.Contains(err.Error(), "--namespaces") ||
		!strings.Contains(err.Error(), "did you mean --namespace") {
		t.Fatalf("error = %q, want unknown flag with namespace suggestion", err.Error())
	}
}

func TestParseReachabilityOnly(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--reachability-only"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !cfg.ReachabilityOnly {
		t.Fatal("ReachabilityOnly = false, want true")
	}
	if cfg.View != ViewResources {
		t.Fatalf("View = %q, want resources", cfg.View)
	}
}

func TestParseReachabilityOnlyRejectsSkipExposure(t *testing.T) {
	_, err := Parse([]string{"k8s", "--reachability-only", "--skip-exposure"})
	if err == nil {
		t.Fatal("Parse returned nil error, want conflicting exposure flags error")
	}
	if !strings.Contains(err.Error(), "reachability-only") || !strings.Contains(err.Error(), "skip-exposure") {
		t.Fatalf("error = %q, want reachability-only/skip-exposure context", err.Error())
	}
}

func TestParseScanReachabilityOnly(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--scan-reachability-only"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !cfg.ScanReachabilityOnly {
		t.Fatal("ScanReachabilityOnly = false, want true")
	}
	if cfg.SkipEnrichment {
		t.Fatal("SkipEnrichment = true, want flag to preserve the user setting and suppress enrichment in execution")
	}
}

func TestParseScanReachabilityOnlyRejectsConflictingFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "skip exposure", args: []string{"k8s", "--scan-reachability-only", "--skip-exposure"}, want: "skip-exposure"},
		{name: "html output", args: []string{"k8s", "--scan-reachability-only", "--html-output", "report.html"}, want: "html-output"},
		{name: "html template", args: []string{"k8s", "--scan-reachability-only", "--html-template", "template.html"}, want: "html-template"},
		{name: "min epss", args: []string{"k8s", "--scan-reachability-only", "--min-epss", "0.5"}, want: "min-epss"},
		{name: "reachability only", args: []string{"k8s", "--scan-reachability-only", "--reachability-only"}, want: "reachability-only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.args)
			if err == nil {
				t.Fatal("Parse returned nil error, want conflict error")
			}
			if !strings.Contains(err.Error(), "scan-reachability-only") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want scan-reachability-only/%s context", err.Error(), tt.want)
			}
		})
	}
}

func TestParseImageSource(t *testing.T) {
	cfg, err := Parse([]string{"image", "--parallel-scans", "2", "gcr.io/example/app:v1", "nginx:1.25"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Source != SourceImage {
		t.Fatalf("Source = %q, want %q", cfg.Source, SourceImage)
	}
	if !reflect.DeepEqual(cfg.ImageRefs, []string{"gcr.io/example/app:v1", "nginx:1.25"}) {
		t.Fatalf("ImageRefs = %#v", cfg.ImageRefs)
	}
	if cfg.ParallelScans != 2 {
		t.Fatalf("ParallelScans = %d, want 2", cfg.ParallelScans)
	}
}

func TestParseImageSourceRequiresImage(t *testing.T) {
	_, err := Parse([]string{"image"})
	if err == nil {
		t.Fatal("Parse returned nil error, want image requirement error")
	}
	if !strings.Contains(err.Error(), "image reference") {
		t.Fatalf("error = %q, want image reference context", err.Error())
	}
}

func TestParseImageSourceRejectsReachabilityOnly(t *testing.T) {
	_, err := Parse([]string{"image", "--reachability-only", "nginx:1.25"})
	if err == nil {
		t.Fatal("Parse returned nil error, want reachability-only rejection")
	}
	if !strings.Contains(err.Error(), "reachability-only") || !strings.Contains(err.Error(), "image") {
		t.Fatalf("error = %q, want reachability-only/image context", err.Error())
	}
}

func TestParseImageSourceRejectsScanReachabilityOnly(t *testing.T) {
	_, err := Parse([]string{"image", "--scan-reachability-only", "nginx:1.25"})
	if err == nil {
		t.Fatal("Parse returned nil error, want scan-reachability-only rejection")
	}
	if !strings.Contains(err.Error(), "scan-reachability-only") || !strings.Contains(err.Error(), "image") {
		t.Fatalf("error = %q, want scan-reachability-only/image context", err.Error())
	}
}

func TestParseImageSourceRejectsClusterFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "namespace", args: []string{"image", "--namespace", "default", "nginx:1.25"}, want: "--namespace"},
		{name: "project", args: []string{"image", "--project", "p", "nginx:1.25"}, want: "--project"},
		{name: "region", args: []string{"image", "--region", "us-east4", "nginx:1.25"}, want: "--region"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.args)
			if err == nil {
				t.Fatal("Parse returned nil error, want source-specific flag rejection")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want %q context", err.Error(), tt.want)
			}
		})
	}
}

func TestParseRejectsConflictingNamespaceScope(t *testing.T) {
	_, err := Parse([]string{"k8s", "--namespace", "prod", "--all-namespaces"})
	if err == nil {
		t.Fatal("Parse returned nil error, want conflicting namespace scope error")
	}
	if !strings.Contains(err.Error(), "all-namespaces") {
		t.Fatalf("error = %q, want all-namespaces context", err.Error())
	}
}

func TestParseNamespaceRejectsInvalidNames(t *testing.T) {
	_, err := Parse([]string{"k8s", "--namespace", "bad/name"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid namespace error")
	}
	if !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("error = %q, want namespace context", err.Error())
	}
}

func TestParseNamespaceRejectsNamesLongerThan63Characters(t *testing.T) {
	_, err := Parse([]string{"k8s", "--namespace", strings.Repeat("a", 64)})
	if err == nil {
		t.Fatal("Parse returned nil error, want namespace length error")
	}
	if !strings.Contains(err.Error(), "63") {
		t.Fatalf("error = %q, want max length context", err.Error())
	}
}

func TestParseRejectsInvalidFormat(t *testing.T) {
	_, err := Parse([]string{"k8s", "--format", "yaml"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid format error")
	}
}

func TestParseNormalizesCaseInsensitiveEnums(t *testing.T) {
	cfg, err := Parse([]string{
		"k8s",
		"--format", "TABLE",
		"--view", "RESOURCES",
		"--cache-cleanup", "ALWAYS",
		"--min-severity", "critical",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Format != FormatTable {
		t.Fatalf("Format = %q, want %q", cfg.Format, FormatTable)
	}
	if cfg.View != ViewResources {
		t.Fatalf("View = %q, want %q", cfg.View, ViewResources)
	}
	if cfg.CacheCleanup != CacheCleanupAlways {
		t.Fatalf("CacheCleanup = %q, want %q", cfg.CacheCleanup, CacheCleanupAlways)
	}
	if cfg.MinSeverity != "CRITICAL" {
		t.Fatalf("MinSeverity = %q, want CRITICAL", cfg.MinSeverity)
	}
}

func TestParseAcceptsCycloneDXFormat(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--format", "cyclonedx"})
	if err != nil {
		t.Fatalf("Parse returned error for cyclonedx format: %v", err)
	}
	if cfg.Format != FormatCycloneDX {
		t.Fatalf("Format = %q, want %q", cfg.Format, FormatCycloneDX)
	}
}

func TestParseRejectsInvalidView(t *testing.T) {
	_, err := Parse([]string{"k8s", "--view", "clusters"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid view error")
	}
}

func TestParseRejectsInvalidSeverity(t *testing.T) {
	_, err := Parse([]string{"k8s", "--min-severity", "SEVERE"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid severity error")
	}
}

func TestParseTimeout(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--timeout", "45s"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Timeout != 45*time.Second {
		t.Fatalf("Timeout = %v, want 45s", cfg.Timeout)
	}

	_, err = Parse([]string{"k8s", "--timeout", "eventually"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid timeout error")
	}

	for _, value := range []string{"0s", "-1s"} {
		t.Run(value, func(t *testing.T) {
			_, err := Parse([]string{"k8s", "--timeout", value})
			if err == nil {
				t.Fatal("Parse returned nil error, want non-positive timeout error")
			}
		})
	}
}

func TestParseMinEPSS(t *testing.T) {
	cfg, err := Parse([]string{"k8s", "--min-epss", "0.72"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.MinEPSS != 0.72 {
		t.Fatalf("MinEPSS = %v, want 0.72", cfg.MinEPSS)
	}

	for _, value := range []string{"-0.2", "1.2", "not-a-number", "NaN", "+Inf", "-Inf"} {
		t.Run(value, func(t *testing.T) {
			_, err := Parse([]string{"k8s", "--min-epss", value})
			if err == nil {
				t.Fatal("Parse returned nil error, want invalid min EPSS error")
			}
		})
	}
}

func TestParseRejectsInvalidScanAndCacheFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "zero parallel scans", args: []string{"k8s", "--parallel-scans", "0"}, want: "parallel-scans"},
		{name: "negative parallel scans", args: []string{"k8s", "--parallel-scans", "-1"}, want: "parallel-scans"},
		{name: "invalid cache cleanup", args: []string{"k8s", "--cache-cleanup", "sometimes"}, want: "cache-cleanup"},
		{name: "negative cache min free gb", args: []string{"k8s", "--cache-min-free-gb", "-1"}, want: "cache-min-free-gb"},
		{name: "negative cache min free percent", args: []string{"k8s", "--cache-min-free-percent", "-1"}, want: "cache-min-free-percent"},
		{name: "cache min free percent over 100", args: []string{"k8s", "--cache-min-free-percent", "101"}, want: "cache-min-free-percent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.args)
			if err == nil {
				t.Fatal("Parse returned nil error, want invalid flag error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want %q context", err.Error(), tt.want)
			}
		})
	}
}

func TestParseHelpIncludesExamplesAndAliasSummary(t *testing.T) {
	var out strings.Builder
	_, err := ParseWithOutput([]string{"--help"}, &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Parse error = %v, want flag.ErrHelp", err)
	}
	help := out.String()
	for _, want := range []string{
		"Common aliases:",
		"-n, --namespace",
		"-o, --output",
		"-f, --format",
		"-q, --quiet",
		"-t, --timeout",
		"-O, --oci-vex-included",
		"Examples:",
		"vdr k8s -n default -f table",
		"vdr cloudrun --project my-gcp-project --region us-east4",
		"vdr image -O nginx:1.25",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help output missing %q:\n%s", want, help)
		}
	}
}
