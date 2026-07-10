package helm

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestTemplateArgsPreservesValuesOrderAndRemoteOptions(t *testing.T) {
	args, err := TemplateArgs(Chart{
		Reference:   "oci://registry.example.com/charts/app",
		Version:     "1.2.3",
		Repository:  "https://charts.example.com",
		ReleaseName: "payments",
		Namespace:   "prod",
		ValuesFiles: []string{"base.yaml", "region.yaml", "prod.yaml"},
		KubeVersion: "1.32.0",
		APIVersions: []string{"gateway.networking.k8s.io/v1", "example.com/v1"},
		IncludeCRDs: true,
	})
	if err != nil {
		t.Fatalf("TemplateArgs returned error: %v", err)
	}
	want := []string{
		"template", "payments", "oci://registry.example.com/charts/app", "--namespace", "prod",
		"--version", "1.2.3",
		"--repo", "https://charts.example.com",
		"--values", "base.yaml",
		"--values", "region.yaml",
		"--values", "prod.yaml",
		"--kube-version", "1.32.0",
		"--api-versions", "gateway.networking.k8s.io/v1",
		"--api-versions", "example.com/v1",
		"--include-crds",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v\nwant = %#v", args, want)
	}
}

func TestTemplateArgsRequiresCoreFields(t *testing.T) {
	for _, chart := range []Chart{
		{ReleaseName: "release", Namespace: "default"},
		{Reference: "./chart", Namespace: "default"},
		{Reference: "./chart", ReleaseName: "release"},
	} {
		if _, err := TemplateArgs(chart); err == nil {
			t.Fatalf("TemplateArgs(%#v) returned nil error", chart)
		}
	}
}

func TestRenderUsesHelmValuesRightmostWins(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	rendered, err := Render(context.Background(), Chart{
		Reference:   "testdata/chart",
		ReleaseName: "ordered-values",
		Namespace:   "prod",
		ValuesFiles: []string{"testdata/chart/values-base.yaml", "testdata/chart/values-prod.yaml"},
	})
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if !strings.Contains(string(rendered), "ghcr.io/acme/app:prod") {
		t.Fatalf("rendered chart did not use rightmost values file:\n%s", rendered)
	}
}
