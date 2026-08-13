package k8scompliance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const defaultTrivyBinary = "trivy"

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

type TrivyRunner struct {
	Binary        string
	CacheDir      string
	CommandRunner CommandRunner
}

type ScanOptions struct {
	// KubeContext is passed to the Trivy CLI as its optional context
	// positional, so it must be a real kubeconfig context name. Leave it empty
	// when running in-cluster; do not substitute a synthetic report identity
	// here or Trivy will fail to resolve it.
	KubeContext string
	Namespaces  []string
	Timeout     time.Duration
	MinSeverity string
}

type rawReport struct {
	ClusterName string        `json:"ClusterName"`
	Resources   []rawResource `json:"Resources"`
}

type rawResource struct {
	Namespace string      `json:"Namespace"`
	Kind      string      `json:"Kind"`
	Name      string      `json:"Name"`
	Results   []rawResult `json:"Results"`
	Error     string      `json:"Error"`
}

type rawResult struct {
	Target         string                     `json:"Target"`
	Class          string                     `json:"Class"`
	Type           string                     `json:"Type"`
	MisconfSummary *MisconfSummary            `json:"MisconfSummary"`
	Checks         []rawDetectedConfiguration `json:"Misconfigurations"`
}

type rawDetectedConfiguration struct {
	Type          string          `json:"Type"`
	ID            string          `json:"ID"`
	AVDID         string          `json:"AVDID"`
	Title         string          `json:"Title"`
	Description   string          `json:"Description"`
	Message       string          `json:"Message"`
	Namespace     string          `json:"Namespace"`
	Query         string          `json:"Query"`
	Resolution    string          `json:"Resolution"`
	Severity      string          `json:"Severity"`
	PrimaryURL    string          `json:"PrimaryURL"`
	References    []string        `json:"References"`
	Status        string          `json:"Status"`
	CauseMetadata json.RawMessage `json:"CauseMetadata"`
	Traces        []string        `json:"Traces"`
}

func (r TrivyRunner) Scan(ctx context.Context, options ScanOptions) ([]ResourceReport, string, error) {
	if options.Timeout <= 0 {
		return nil, "", errors.New("Kubernetes compliance scan timeout must be greater than zero")
	}
	args := []string{
		"k8s",
		"--format", "json",
		"--report", "all",
		"--scanners", "misconfig,rbac",
		"--skip-images",
		"--disable-node-collector",
		"--skip-version-check",
		"--timeout", options.Timeout.String(),
	}
	if r.CacheDir != "" {
		args = append(args, "--cache-dir", r.CacheDir)
	}
	if len(options.Namespaces) > 0 {
		namespaces := append([]string(nil), options.Namespaces...)
		sort.Strings(namespaces)
		args = append(args, "--include-namespaces", strings.Join(namespaces, ","))
	}
	if severities := severitiesAtOrAbove(options.MinSeverity); len(severities) > 0 {
		args = append(args, "--severity", strings.Join(severities, ","))
	}
	if options.KubeContext != "" {
		args = append(args, options.KubeContext)
	}

	stdout, stderr, err := r.commandRunner().Run(ctx, r.binary(), args...)
	if err != nil {
		return nil, "", fmt.Errorf("Trivy Kubernetes compliance scan failed: %w: %s", err, string(bytes.TrimSpace(stderr)))
	}
	var scanned rawReport
	if err := json.Unmarshal(stdout, &scanned); err != nil {
		return nil, "", fmt.Errorf("parse Trivy Kubernetes compliance report: %w", err)
	}
	return convertResources(scanned.Resources), scanned.ClusterName, nil
}

func (r TrivyRunner) binary() string {
	if r.Binary != "" {
		return r.Binary
	}
	return defaultTrivyBinary
}

func (r TrivyRunner) commandRunner() CommandRunner {
	if r.CommandRunner != nil {
		return r.CommandRunner
	}
	return execCommandRunner{}
}

func severitiesAtOrAbove(minimum string) []string {
	all := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	minimum = strings.ToUpper(strings.TrimSpace(minimum))
	if minimum == "" {
		return nil
	}
	for index, severity := range all {
		if severity == minimum {
			return all[index:]
		}
	}
	return nil
}

func convertResources(resources []rawResource) []ResourceReport {
	converted := make([]ResourceReport, 0, len(resources))
	for _, resource := range resources {
		out := ResourceReport{
			Resource: ObjectRef{
				Kind:      resource.Kind,
				Namespace: resource.Namespace,
				Name:      resource.Name,
			},
			Error: resource.Error,
		}
		for _, result := range resource.Results {
			convertedResult := Result{
				Target:         result.Target,
				Class:          result.Class,
				Type:           result.Type,
				MisconfSummary: result.MisconfSummary,
			}
			for _, check := range result.Checks {
				causeMetadata := check.CauseMetadata
				if bytes.Equal(bytes.TrimSpace(causeMetadata), []byte("null")) {
					causeMetadata = nil
				}
				convertedResult.Checks = append(convertedResult.Checks, Check{
					Type:          check.Type,
					ID:            check.ID,
					AVDID:         check.AVDID,
					Title:         check.Title,
					Description:   check.Description,
					Message:       check.Message,
					Namespace:     check.Namespace,
					Query:         check.Query,
					Resolution:    check.Resolution,
					Severity:      strings.ToUpper(check.Severity),
					PrimaryURL:    check.PrimaryURL,
					References:    check.References,
					Status:        strings.ToUpper(check.Status),
					CauseMetadata: causeMetadata,
					Traces:        check.Traces,
				})
			}
			out.Results = append(out.Results, convertedResult)
		}
		converted = append(converted, out)
	}
	sort.SliceStable(converted, func(i, j int) bool {
		left, right := converted[i].Resource, converted[j].Resource
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Name < right.Name
	})
	return converted
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
