package config

import (
	"bytes"
	"strings"
	"testing"
)

func TestCloudConfigOnlyAppliesToECSAndCloudRun(t *testing.T) {
	for _, source := range []string{"ecs", "cloudrun"} {
		args := []string{source, "--region", "us-east-1", "--cloud-config", "vdr-cloud.yaml"}
		if source == "cloudrun" {
			args = append(args, "--project", "example-project")
		}
		cfg, err := Parse(args)
		if err != nil || cfg.CloudConfig != "vdr-cloud.yaml" {
			t.Fatalf("%s: %v", source, err)
		}
	}
	if _, err := Parse([]string{"k8s", "--all-namespaces", "--cloud-config", "vdr-cloud.yaml"}); err == nil {
		t.Fatal("Kubernetes accepted cloud policy")
	}
}

func TestCloudConfigHelpExplainsManagedPlatformAssociation(t *testing.T) {
	var out bytes.Buffer
	_, _ = ParseWithOutput([]string{"ecs", "--help"}, &out)
	for _, fragment := range []string{"cloud-config", "standalone", "stackArmor-managed", "recalculates"} {
		if !strings.Contains(out.String(), fragment) {
			t.Fatalf("help missing %q", fragment)
		}
	}
}
