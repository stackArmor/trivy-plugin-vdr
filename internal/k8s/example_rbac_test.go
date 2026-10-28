package k8s

import (
	"bytes"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestExampleRBACCoversCollectorReads keeps examples/rbac/vdr-read.yaml, the
// README's canonical ClusterRole, in step with the API reads the collector
// makes. Add a read here when the collector gains one.
func TestExampleRBACCoversCollectorReads(t *testing.T) {
	data, err := os.ReadFile("../../examples/rbac/vdr-read.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	granted := map[[3]string]bool{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc struct {
			Kind  string `yaml:"kind"`
			Rules []struct {
				APIGroups []string `yaml:"apiGroups"`
				Resources []string `yaml:"resources"`
				Verbs     []string `yaml:"verbs"`
			} `yaml:"rules"`
		}
		if err := decoder.Decode(&doc); err != nil {
			break
		}
		if doc.Kind != "ClusterRole" {
			continue
		}
		for _, rule := range doc.Rules {
			for _, group := range rule.APIGroups {
				for _, resource := range rule.Resources {
					for _, verb := range rule.Verbs {
						granted[[3]string{group, resource, verb}] = true
					}
				}
			}
		}
	}
	if len(granted) == 0 {
		t.Fatal("example declares no ClusterRole rules")
	}

	required := [][3]string{
		{"", "namespaces", "get"},
		{"", "namespaces", "list"},
		{"", "pods", "list"},
		{"", "replicationcontrollers", "list"},
		{"", "services", "list"},
		{"", "configmaps", "get"},
		{"", "nodes", "list"},
		{"", "secrets", "get"},
		{"apps", "deployments", "list"},
		{"apps", "replicasets", "list"},
		{"apps", "statefulsets", "list"},
		{"apps", "daemonsets", "list"},
		{"batch", "jobs", "list"},
		{"batch", "cronjobs", "list"},
		{"networking.k8s.io", "ingresses", "list"},
		{"networking.k8s.io", "ingressclasses", "list"},
		{"networking.k8s.io", "networkpolicies", "list"},
	}
	for _, resource := range exposureResources {
		required = append(required, [3]string{resource.gvr.Group, resource.gvr.Resource, "list"})
	}
	for _, want := range required {
		if !granted[want] {
			t.Errorf("examples/rbac/vdr-read.yaml does not grant %s on %q in API group %q", want[2], want[1], want[0])
		}
	}
}
