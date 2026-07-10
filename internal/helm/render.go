package helm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Chart describes one independent Helm release to render. ValuesFiles remains
// ordered because Helm merges files from left to right and the rightmost file
// takes precedence.
type Chart struct {
	Reference   string
	Version     string
	Repository  string
	ReleaseName string
	Namespace   string
	ValuesFiles []string
	KubeVersion string
	APIVersions []string
	IncludeCRDs bool
}

// TemplateArgs returns the exact helm template arguments for chart. It is kept
// separate from Render both for testability and to make preservation of values
// ordering explicit.
func TemplateArgs(chart Chart) ([]string, error) {
	if strings.TrimSpace(chart.Reference) == "" {
		return nil, errors.New("Helm chart reference is required")
	}
	if strings.TrimSpace(chart.ReleaseName) == "" {
		return nil, errors.New("Helm release name is required")
	}
	if strings.TrimSpace(chart.Namespace) == "" {
		return nil, errors.New("Helm namespace is required")
	}

	args := []string{"template", chart.ReleaseName, chart.Reference, "--namespace", chart.Namespace}
	if chart.Version != "" {
		args = append(args, "--version", chart.Version)
	}
	if chart.Repository != "" {
		args = append(args, "--repo", chart.Repository)
	}
	for _, path := range chart.ValuesFiles {
		args = append(args, "--values", path)
	}
	if chart.KubeVersion != "" {
		args = append(args, "--kube-version", chart.KubeVersion)
	}
	for _, version := range chart.APIVersions {
		args = append(args, "--api-versions", version)
	}
	if chart.IncludeCRDs {
		args = append(args, "--include-crds")
	}
	return args, nil
}

// Render runs the installed Helm client. Local directories and archives,
// configured repository references, direct --repo references, and oci://
// references are all handled by Helm itself. Repository and registry
// authentication therefore follows the user's existing Helm configuration.
func Render(ctx context.Context, chart Chart) ([]byte, error) {
	args, err := TemplateArgs(chart)
	if err != nil {
		return nil, err
	}
	binary, err := exec.LookPath("helm")
	if err != nil {
		return nil, errors.New("Helm executable not found on PATH; install Helm to scan charts")
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return nil, fmt.Errorf("helm template %q failed: %s", chart.Reference, detail)
	}
	return stdout.Bytes(), nil
}
