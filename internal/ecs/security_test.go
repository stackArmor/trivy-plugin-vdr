package ecs

import (
	"reflect"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/report"
)

func TestSecurityMetadataIsCapturedForTaskDefinition(t *testing.T) {
	taskDefinition := TaskDefinition{
		Region:                  "us-east-1",
		Arn:                     "arn:aws:ecs:us-east-1:123:task-definition/api:7",
		Family:                  "api",
		Revision:                7,
		NetworkMode:             "awsvpc",
		ExecutionRoleArn:        "arn:aws:iam::123:role/exec",
		TaskRoleArn:             "arn:aws:iam::123:role/task",
		RequiresCompatibilities: []string{"FARGATE", "EC2"},
		Containers: []ContainerDefinition{{
			Name:                   "api",
			Image:                  "example.com/api:1",
			Privileged:             true,
			ReadonlyRootFilesystem: true,
			User:                   "1000",
			CapabilitiesAdd:        []string{"NET_ADMIN"},
			CapabilitiesDrop:       []string{"ALL"},
			InitProcessEnabled:     boolPtr(true),
			LogDriver:              "awslogs",
			Secrets: []SecretRef{{
				Name:      "DATABASE_PASSWORD",
				ValueFrom: "arn:aws:secretsmanager:us-east-1:123:secret:db",
			}},
			EnvironmentFiles: []EnvironmentFileRef{{
				Type:  "s3",
				Value: "arn:aws:s3:::bucket/env",
			}},
		}},
	}

	got := buildInventoryFromTaskDefinitions([]TaskDefinition{taskDefinition})

	if len(got.Resources) != 1 || len(got.Resources[0].Images) != 1 {
		t.Fatalf("inventory = %#v, want one resource/image", got)
	}
	image := got.Resources[0].Images[0]
	if image.Security == nil {
		t.Fatal("Security = nil, want container security")
	}
	if image.Security.Privileged == nil || !*image.Security.Privileged {
		t.Fatalf("Privileged = %#v, want true", image.Security.Privileged)
	}
	if image.Security.ReadOnlyRootFilesystem == nil || !*image.Security.ReadOnlyRootFilesystem {
		t.Fatalf("ReadOnlyRootFilesystem = %#v, want true", image.Security.ReadOnlyRootFilesystem)
	}
	if !reflect.DeepEqual(image.Security.CapabilitiesAdd, []string{"NET_ADMIN"}) {
		t.Fatalf("CapabilitiesAdd = %#v", image.Security.CapabilitiesAdd)
	}
	if !reflect.DeepEqual(image.Security.CapabilitiesDrop, []string{"ALL"}) {
		t.Fatalf("CapabilitiesDrop = %#v", image.Security.CapabilitiesDrop)
	}

	metadata := got.Resources[0].ProviderMetadata
	want := map[string]string{
		"ecs.executionRoleArn":        "arn:aws:iam::123:role/exec",
		"ecs.taskRoleArn":             "arn:aws:iam::123:role/task",
		"ecs.networkMode":             "awsvpc",
		"ecs.requiresCompatibilities": "EC2,FARGATE",
		"ecs.container.api.user":      "1000",
		"ecs.container.api.init":      "true",
		"ecs.container.api.logDriver": "awslogs",
		"ecs.container.api.secrets":   "1",
		"ecs.container.api.envFiles":  "1",
	}
	for key, wantValue := range want {
		if metadata[key] != wantValue {
			t.Fatalf("metadata[%q] = %q, want %q (all metadata %#v)", key, metadata[key], wantValue, metadata)
		}
	}
	for key, value := range metadata {
		if value == "arn:aws:secretsmanager:us-east-1:123:secret:db" {
			t.Fatalf("metadata leaked secret source in %s", key)
		}
	}
}

func TestSecurityMetadataIsPreservedInResourceReports(t *testing.T) {
	ref := model.ResourceRef{Kind: "TaskDefinition", Provider: Provider, Region: "us-east-1", Name: "api:7"}
	inventory := &model.Inventory{Resources: []model.ResourceInventory{{
		Resource:         ref,
		ProviderMetadata: map[string]string{"ecs.networkMode": "awsvpc"},
		Images:           []model.ContainerImage{{Name: "api", ContainerType: "container", ImageRef: "example.com/api:1"}},
	}}}

	scanReport := report.Build(inventory, nil, nil, report.Options{View: report.ViewResources})

	if len(scanReport.Resources) != 1 {
		t.Fatalf("resources = %#v, want one", scanReport.Resources)
	}
	if scanReport.Resources[0].ProviderMetadata["ecs.networkMode"] != "awsvpc" {
		t.Fatalf("ProviderMetadata = %#v", scanReport.Resources[0].ProviderMetadata)
	}
}
