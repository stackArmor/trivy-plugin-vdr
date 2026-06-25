package config

import (
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
	if cfg.SkipEnrichment || cfg.SkipExposure || cfg.Debug {
		t.Fatalf("SkipEnrichment/SkipExposure/Debug = %v/%v/%v, want all false", cfg.SkipEnrichment, cfg.SkipExposure, cfg.Debug)
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
