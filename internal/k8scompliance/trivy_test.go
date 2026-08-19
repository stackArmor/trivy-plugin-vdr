package k8scompliance

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

type recordingCommandRunner struct {
	name   string
	args   []string
	stdout []byte
	stderr []byte
	err    error
}

func (r *recordingCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.stdout, r.stderr, r.err
}

func TestTrivyRunnerUsesBuiltInReadOnlyKubernetesRules(t *testing.T) {
	command := &recordingCommandRunner{stdout: []byte(`{
		"ClusterName": "dev-cluster",
		"Resources": [{
			"Namespace": "prod",
			"Kind": "Deployment",
			"Name": "api",
			"Results": [{
				"Target": "Deployment/api",
				"Class": "config",
				"Type": "kubernetes",
				"MisconfSummary": {"Successes": 7, "Failures": 1},
				"Misconfigurations": [{
					"ID": "KSV001",
					"AVDID": "AVD-KSV-0001",
					"Title": "Privileged container",
					"Message": "Container is privileged",
					"Severity": "HIGH",
					"Status": "FAIL",
					"CauseMetadata": {"Resource": "securityContext.privileged"}
				}]
			}]
		}]
	}`)}
	runner := TrivyRunner{
		Binary:        "custom-trivy",
		CacheDir:      "/tmp/trivy-cache",
		CommandRunner: command,
	}

	resources, clusterName, err := runner.Scan(context.Background(), ScanOptions{
		KubeContext: "dev-context",
		Namespaces:  []string{"prod", "apps"},
		Timeout:     2 * time.Minute,
		MinSeverity: "HIGH",
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if command.name != "custom-trivy" {
		t.Fatalf("binary = %q, want custom-trivy", command.name)
	}
	for _, want := range []string{
		"k8s",
		"--format", "json",
		"--report", "all",
		"--scanners", "misconfig,rbac",
		"--skip-images",
		"--disable-node-collector",
		"--skip-version-check",
		"--timeout", "2m0s",
		"--cache-dir", "/tmp/trivy-cache",
		"--include-namespaces", "apps,prod",
		"--severity", "HIGH,CRITICAL",
		"dev-context",
	} {
		if !slices.Contains(command.args, want) {
			t.Fatalf("Trivy arguments %#v do not contain %q", command.args, want)
		}
	}
	if slices.Contains(command.args, "--compliance") {
		t.Fatalf("Trivy arguments unexpectedly select a named compliance profile: %#v", command.args)
	}
	if clusterName != "dev-cluster" {
		t.Fatalf("clusterName = %q, want dev-cluster", clusterName)
	}
	if len(resources) != 1 || len(resources[0].Results) != 1 || len(resources[0].Results[0].Checks) != 1 {
		t.Fatalf("resources = %#v", resources)
	}
	check := resources[0].Results[0].Checks[0]
	if check.ID != "KSV001" || check.Severity != "HIGH" || len(check.CauseMetadata) == 0 {
		t.Fatalf("check = %#v", check)
	}
}

func TestTrivyRunnerReportsCommandFailure(t *testing.T) {
	command := &recordingCommandRunner{
		stderr: []byte("permission denied"),
		err:    errors.New("exit status 1"),
	}
	_, _, err := (TrivyRunner{CommandRunner: command}).Scan(context.Background(), ScanOptions{Timeout: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Scan error = %v, want stderr context", err)
	}
}

func TestSeveritiesAtOrAbove(t *testing.T) {
	if got := strings.Join(severitiesAtOrAbove("medium"), ","); got != "MEDIUM,HIGH,CRITICAL" {
		t.Fatalf("severitiesAtOrAbove(medium) = %q", got)
	}
	if got := severitiesAtOrAbove(""); got != nil {
		t.Fatalf("severitiesAtOrAbove(empty) = %#v, want nil", got)
	}
}

func TestScanPassesExcludeNamespacesFlag(t *testing.T) {
	runnerCmd := &recordingCommandRunner{
		stdout: []byte(`{"ClusterName":"test-cluster","Resources":[]}`),
	}
	runner := TrivyRunner{
		CommandRunner: runnerCmd,
	}
	_, _, err := runner.Scan(context.Background(), ScanOptions{
		Timeout:           time.Minute,
		ExcludeNamespaces: []string{"monitoring", "kube-system"},
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	found := false
	for i, arg := range runnerCmd.args {
		if arg == "--exclude-namespaces" && i+1 < len(runnerCmd.args) {
			if runnerCmd.args[i+1] == "kube-system,monitoring" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("expected --exclude-namespaces kube-system,monitoring in args, got %v", runnerCmd.args)
	}
}
