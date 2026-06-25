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

	cfg, err := Parse([]string{})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	wantCacheDir := filepath.Join(home, ".cache", "trivy", "k8s-vdr")
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
	cfg, err := Parse([]string{"--namespace", "prod", "--namespace", "dev"})
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

func TestParseNamespaceRejectsInvalidNames(t *testing.T) {
	_, err := Parse([]string{"--namespace", "bad/name"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid namespace error")
	}
	if !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("error = %q, want namespace context", err.Error())
	}
}

func TestParseRejectsInvalidFormat(t *testing.T) {
	_, err := Parse([]string{"--format", "yaml"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid format error")
	}
}

func TestParseRejectsInvalidView(t *testing.T) {
	_, err := Parse([]string{"--view", "clusters"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid view error")
	}
}

func TestParseRejectsInvalidSeverity(t *testing.T) {
	_, err := Parse([]string{"--min-severity", "SEVERE"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid severity error")
	}
}

func TestParseTimeout(t *testing.T) {
	cfg, err := Parse([]string{"--timeout", "45s"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Timeout != 45*time.Second {
		t.Fatalf("Timeout = %v, want 45s", cfg.Timeout)
	}

	_, err = Parse([]string{"--timeout", "eventually"})
	if err == nil {
		t.Fatal("Parse returned nil error, want invalid timeout error")
	}
}

func TestParseMinEPSS(t *testing.T) {
	cfg, err := Parse([]string{"--min-epss", "0.72"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.MinEPSS != 0.72 {
		t.Fatalf("MinEPSS = %v, want 0.72", cfg.MinEPSS)
	}

	for _, value := range []string{"-0.2", "1.2", "not-a-number"} {
		t.Run(value, func(t *testing.T) {
			_, err := Parse([]string{"--min-epss", value})
			if err == nil {
				t.Fatal("Parse returned nil error, want invalid min EPSS error")
			}
		})
	}
}
