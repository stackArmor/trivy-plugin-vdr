package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/config"
	"github.com/stackArmor/trivy-plugin-vdr/internal/enrich"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestRunK8sPassesPullSecretAuthsToRegistryBuild(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runK8s" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Build" {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "registry" {
				return true
			}
			if len(call.Args) < 3 {
				return true
			}
			if ident, ok := call.Args[2].(*ast.Ident); ok && ident.Name == "secretAuths" {
				found = true
			}
			return true
		})
		return false
	})

	if !found {
		t.Fatal("runK8s does not pass secretAuths to registry.Build")
	}
}

func TestRunK8sSetsExcludeNamespacesInK8sOptions(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runK8s" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			comp, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := comp.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Options" {
				return true
			}
			for _, elt := range comp.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "ExcludeNamespaces" {
					continue
				}
				val, ok := kv.Value.(*ast.SelectorExpr)
				if ok && val.Sel.Name == "ExcludeNamespaces" {
					found = true
				}
			}
			return true
		})
		return false
	})

	if !found {
		t.Fatal("runK8s does not set ExcludeNamespaces in k8s.Options")
	}
}

func TestLogIncompatibleClusterConfigGivesMigrationGuidance(t *testing.T) {
	var output bytes.Buffer
	logIncompatibleClusterConfig(log.NewWithWriter(&output, log.LevelQuiet), fmt.Errorf("unknown securityImpactProfile %q", "old-value"))

	for _, want := range []string{
		"ERROR",
		"invalid, incompatible, or uses an unsupported older format",
		`unknown securityImpactProfile "old-value"`,
		"<disclosure>.<trusted-change>.<dependency>",
		"reassessed values",
		vdrConfigMapAIHelpURL,
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("log output missing %q:\n%s", want, output.String())
		}
	}
}

func TestRunHelmReachabilityOnlyEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	cfg, err := config.Parse([]string{
		"helm", "../../internal/helm/testdata/chart",
		"-f", "../../internal/helm/testdata/chart/values-base.yaml",
		"-f", "../../internal/helm/testdata/chart/values-prod.yaml",
		"--reachability-only",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	var output bytes.Buffer
	if err := runHelm(context.Background(), cfg, log.NewWithWriter(io.Discard, log.LevelQuiet), &output); err != nil {
		t.Fatalf("runHelm returned error: %v", err)
	}
	for _, want := range []string{`"contextName": "helm:../../internal/helm/testdata/chart"`, `"imageRef": "ghcr.io/acme/app:prod"`, `"namespace": "default"`} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("report missing %s:\n%s", want, output.String())
		}
	}
}

func TestRunEnrichReportAddsPinnedTaxonomyWithoutRescan(t *testing.T) {
	inputReport := model.Report{
		GeneratedAt:    fixedMainTestTime(),
		ScannerVersion: "0.72.0",
		PluginVersion:  "3.0.0",
		Summary:        model.Summary{Findings: 2, FindingsWithSpecificCWE: 1},
		Findings: []model.Finding{
			{ID: "CVE-2026-0094", PackageName: "parser", InstalledVersion: "1.0", Severity: "HIGH", CWEs: []string{"CWE-94"}},
			{ID: "CVE-2026-0000", PackageName: "other", InstalledVersion: "2.0", Severity: "MEDIUM"},
		},
	}
	var input bytes.Buffer
	if err := json.NewEncoder(&input).Encode(inputReport); err != nil {
		t.Fatalf("encode input report: %v", err)
	}
	var output bytes.Buffer

	if err := runEnrichReport([]string{"--input", "-"}, &input, &output); err != nil {
		t.Fatalf("runEnrichReport returned error: %v", err)
	}

	var got model.Report
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode enriched report: %v", err)
	}
	if got.ReportSchemaVersion != "3" || got.ChainCatalog == nil ||
		got.ChainCatalog.CAPECVersion != "3.9" || got.ChainCatalog.ATTACKVersion != "19.1" {
		t.Fatalf("report/catalog metadata = %q/%#v", got.ReportSchemaVersion, got.ChainCatalog)
	}
	if got.Summary.ChainTaxonomy == nil || got.Summary.ChainTaxonomy.MappedFindings != 1 ||
		got.Summary.ChainTaxonomy.UnknownFindings != 1 {
		t.Fatalf("taxonomy summary = %#v", got.Summary.ChainTaxonomy)
	}
	if len(got.Findings) != 2 || got.Findings[0].ChainTaxonomy == nil ||
		got.Findings[0].ChainTaxonomy.Status != "mapped" ||
		got.Findings[0].ChainTaxonomy.PredecessorStatus == "" ||
		got.Findings[0].ChainTaxonomy.SuccessorStatus == "" ||
		len(got.Findings[0].ChainTaxonomy.Paths) == 0 {
		t.Fatalf("findings = %#v, want path-preserving taxonomy", got.Findings)
	}
	if got.Findings[1].ChainTaxonomy == nil || got.Findings[1].ChainTaxonomy.Status != "unknown" ||
		got.Findings[1].ChainTaxonomy.PredecessorStatus != "unknown" ||
		got.Findings[1].ChainTaxonomy.SuccessorStatus != "unknown" {
		t.Fatalf("unknown finding taxonomy = %#v", got.Findings[1].ChainTaxonomy)
	}
}

func TestRunEnrichReportRejectsUnsupportedSchema(t *testing.T) {
	var input bytes.Buffer
	if err := json.NewEncoder(&input).Encode(model.Report{ReportSchemaVersion: "999"}); err != nil {
		t.Fatalf("encode input report: %v", err)
	}
	err := runEnrichReport([]string{"--input", "-"}, &input, io.Discard)
	if err == nil || !strings.Contains(err.Error(), `unsupported VDR report schema "999"`) {
		t.Fatalf("runEnrichReport error = %v", err)
	}
}

func TestRunEnrichReportMigratesLegacyEntrypointToCAPECTransitions(t *testing.T) {
	input := strings.NewReader(`{
		"reportSchemaVersion":"2",
		"generatedAt":"2026-07-28T12:00:00Z",
		"summary":{"resources":1,"images":1,"findings":2,"findingsWithSpecificCwe":2},
		"findings":[
			{
				"id":"CVE-2026-1000",
				"packageName":"network-parser",
				"installedVersion":"1.0",
				"severity":"HIGH",
				"cvssVector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"cwes":["CWE-120"],
				"chainableEntrypoint":{"classification":"possible","policyVersion":"chainable-entrypoint-v2"},
				"affected":[{"resource":{"kind":"Deployment","namespace":"prod","name":"api","containerName":"app"},"exposure":{"internetAccessible":true}}]
			},
			{
				"id":"CVE-2026-2000",
				"packageName":"privileged-helper",
				"installedVersion":"2.0",
				"severity":"HIGH",
				"cvssVector":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
				"cwes":["CWE-648"],
				"affected":[{"resource":{"kind":"Deployment","namespace":"prod","name":"api","containerName":"app"},"exposure":{"internetAccessible":true}}]
			}
		]
	}`)
	var output bytes.Buffer

	if err := runEnrichReport([]string{"--input", "-"}, input, &output); err != nil {
		t.Fatalf("runEnrichReport returned error: %v", err)
	}
	if strings.Contains(output.String(), "chainableEntrypoint") {
		t.Fatalf("legacy chainableEntrypoint survived schema migration:\n%s", output.String())
	}
	var got model.Report
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode enriched report: %v", err)
	}
	if got.ReportSchemaVersion != "3" || len(got.CAPECTransitions) == 0 {
		t.Fatalf("schema/transitions = %q/%#v", got.ReportSchemaVersion, got.CAPECTransitions)
	}
	var matched bool
	for _, transition := range got.CAPECTransitions {
		if transition.SourceCAPECID == "CAPEC-100" && transition.TargetCAPECID == "CAPEC-234" &&
			transition.Upstream.ID == "CVE-2026-1000" && transition.Downstream.ID == "CVE-2026-2000" {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("CAPECTransitions = %#v, want CAPEC-100 -> CAPEC-234", got.CAPECTransitions)
	}
}

func fixedMainTestTime() time.Time {
	return time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
}

func TestEnrichmentWarningsFormatting(t *testing.T) {
	warnings := []enrich.Warning{
		{Source: "EPSS", Message: "failed to load dataset: connection reset"},
		{Source: "Vulnrichment", CVEID: "CVE-2026-1234", Message: "fetch Vulnrichment data for CVE-2026-1234: 502 bad gateway"},
		{Source: "Vulnrichment", Message: "source unavailable (circuit breaker tripped; skipped for remaining findings)"},
	}
	formatted := enrichmentWarnings(warnings)
	if len(formatted) != 3 {
		t.Fatalf("formatted length = %d, want 3", len(formatted))
	}
	if formatted[0] != "EPSS: failed to load dataset: connection reset" {
		t.Errorf("formatted[0] = %q", formatted[0])
	}
	if formatted[1] != "Vulnrichment (CVE-2026-1234): fetch Vulnrichment data for CVE-2026-1234: 502 bad gateway" {
		t.Errorf("formatted[1] = %q", formatted[1])
	}
	if formatted[2] != "Vulnrichment: source unavailable (circuit breaker tripped; skipped for remaining findings)" {
		t.Errorf("formatted[2] = %q", formatted[2])
	}
}

func TestReportInventoryIncludesEnrichmentWarnings(t *testing.T) {
	inventory := &model.Inventory{
		ContextName: "test-cluster",
	}
	findings := []model.Finding{
		{ID: "CVE-2026-1000", Severity: "HIGH"},
	}
	warnings := []string{
		"EPSS: failed to load dataset: 502 bad gateway",
		"Vulnrichment (CVE-2026-1000): fetch failed",
	}
	cfg := config.Config{
		Format: config.FormatJSON,
	}
	var output bytes.Buffer
	err := reportInventory(context.Background(), cfg, log.NewWithWriter(io.Discard, log.LevelQuiet), &output, inventory, findings, warnings, nil, nil)
	if err != nil {
		t.Fatalf("reportInventory returned error: %v", err)
	}
	var rep model.Report
	if err := json.Unmarshal(output.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(rep.Warnings) != 2 {
		t.Fatalf("report warnings length = %d, want 2", len(rep.Warnings))
	}
	if rep.Warnings[0] != warnings[0] || rep.Warnings[1] != warnings[1] {
		t.Errorf("report warnings = %v, want %v", rep.Warnings, warnings)
	}
}

func TestEnrichmentContextErrorAppendsWarning(t *testing.T) {
	warnings := []string{}
	err := context.Canceled
	warnings = append(warnings, fmt.Sprintf("Enrichment: incomplete (%v)", err))
	if len(warnings) != 1 || warnings[0] != "Enrichment: incomplete (context canceled)" {
		t.Errorf("warnings = %v, want ['Enrichment: incomplete (context canceled)']", warnings)
	}
}
