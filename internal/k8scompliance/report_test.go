package k8scompliance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testComplianceReport() Report {
	parent := ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "api"}
	return BuildReport([]ResourceReport{{
		Resource:         ObjectRef{APIVersion: "v1", Kind: "Pod", Namespace: "default", Name: "api-123"},
		ParentController: &parent,
		Results: []Result{{
			Target:         "Pod/api-123",
			MisconfSummary: &MisconfSummary{Successes: 5, Failures: 1},
			Checks: []Check{{
				ID:       "KSV001",
				Severity: "HIGH",
				Status:   "FAIL",
				Title:    "Privileged container",
				Message:  "Container is privileged",
			}},
		}},
	}}, ReportOptions{
		ScannerVersion: "0.72.0",
		PluginVersion:  "4.1.0",
		ClusterName:    "dev",
		GeneratedAt:    time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	})
}

func TestBuildReportSummarizesFailures(t *testing.T) {
	report := testComplianceReport()
	if report.ReportSchemaVersion != ReportSchemaVersion {
		t.Fatalf("schema = %q, want %q", report.ReportSchemaVersion, ReportSchemaVersion)
	}
	if report.Summary.Resources != 1 || report.Summary.FailedResources != 1 || report.Summary.FailedChecks != 1 {
		t.Fatalf("summary = %#v", report.Summary)
	}
	if report.Summary.BySeverity["HIGH"] != 1 {
		t.Fatalf("severity summary = %#v", report.Summary.BySeverity)
	}
}

func TestRenderTableMirrorsTrivyResourceGroupingAndShowsParent(t *testing.T) {
	var output bytes.Buffer
	if err := RenderTable(&output, testComplianceReport()); err != nil {
		t.Fatalf("RenderTable returned error: %v", err)
	}
	for _, want := range []string{
		"namespace: default, pod: api-123 (parent: Deployment/api)",
		"Tests: 6 (SUCCESSES: 5, FAILURES: 1)",
		"ID",
		"SEVERITY",
		"KSV001",
		"HIGH",
		"Privileged container",
		"Summary: 1 resources, 1 failed resources, 1 failed checks",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("table missing %q:\n%s", want, output.String())
		}
	}
}

func TestRenderJSONUsesSeparateComplianceSchema(t *testing.T) {
	var output bytes.Buffer
	if err := RenderJSON(&output, testComplianceReport()); err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(output.Bytes(), &raw); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if raw["reportSchemaVersion"] != ReportSchemaVersion {
		t.Fatalf("reportSchemaVersion = %#v", raw["reportSchemaVersion"])
	}
	for _, legacyField := range []string{"findings", "images", "chainCatalog", "capecTransitions"} {
		if _, exists := raw[legacyField]; exists {
			t.Fatalf("compliance JSON unexpectedly contains vulnerability-report field %q", legacyField)
		}
	}
}
