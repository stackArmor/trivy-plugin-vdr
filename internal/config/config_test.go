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
	if cfg.ImageSrc != "registry" {
		t.Fatalf("ImageSrc = %q, want registry", cfg.ImageSrc)
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
	if cfg.SkipEnrichment || cfg.RefreshEnrichment || cfg.SkipExposure || cfg.Debug {
		t.Fatalf("SkipEnrichment/RefreshEnrichment/SkipExposure/Debug = %v/%v/%v/%v, want all false", cfg.SkipEnrichment, cfg.RefreshEnrichment, cfg.SkipExposure, cfg.Debug)
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

func TestParseReservedSourcesReturnNotImplemented(t *testing.T) {
	for _, source := range []string{"ecs", "image"} {
		t.Run(source, func(t *testing.T) {
			_, err := Parse([]string{source})
			if err == nil {
				t.Fatal("Parse returned nil error, want not implemented error")
			}
			if !strings.Contains(err.Error(), `source "`+source+`" is not implemented yet`) {
				t.Fatalf("error = %q, want not implemented source context", err.Error())
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
