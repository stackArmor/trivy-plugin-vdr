package main

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/config"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
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

func TestLogIncompatibleClusterConfigGivesMigrationGuidance(t *testing.T) {
	var output bytes.Buffer
	logIncompatibleClusterConfig(log.NewWithWriter(&output, log.LevelQuiet), fmt.Errorf("unknown archetype %q", "old-value"))

	for _, want := range []string{
		"ERROR",
		"invalid, incompatible, or uses an unsupported older format",
		`unknown archetype "old-value"`,
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
