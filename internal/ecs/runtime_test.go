package ecs

import (
	"reflect"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestRuntimeClassifiesObservedRunningService(t *testing.T) {
	taskDefinitions := []TaskDefinition{{Arn: "arn:aws:ecs:us-east-1:123:task-definition/api:7", Family: "api", Revision: 7}}
	signals := []RuntimeSignal{{
		TaskDefinitionArn: "arn:aws:ecs:us-east-1:123:task-definition/api:7",
		Source:            RuntimeSourceService,
		Cluster:           "prod",
		Service:           "api",
		DesiredCount:      2,
		RunningCount:      1,
	}}

	got := AnalyzeRuntime(taskDefinitions, signals)
	runtime := got["api:7"]
	if runtime.Status != RuntimeObservedRunning {
		t.Fatalf("status = %q, want %q", runtime.Status, RuntimeObservedRunning)
	}
	if !runtime.Observed {
		t.Fatal("Observed = false, want true")
	}
	if len(runtime.Evidence) == 0 {
		t.Fatalf("Evidence = %#v, want service evidence", runtime.Evidence)
	}
}

func TestRuntimeClassifiesServiceDesiredScheduledStandaloneAndDefinedOnly(t *testing.T) {
	taskDefinitions := []TaskDefinition{
		{Arn: "arn:aws:ecs:us-east-1:123:task-definition/api:8", Family: "api", Revision: 8},
		{Arn: "arn:aws:ecs:us-east-1:123:task-definition/batch:3", Family: "batch", Revision: 3},
		{Arn: "arn:aws:ecs:us-east-1:123:task-definition/oneoff:1", Family: "oneoff", Revision: 1},
		{Arn: "arn:aws:ecs:us-east-1:123:task-definition/dormant:4", Family: "dormant", Revision: 4},
	}
	signals := []RuntimeSignal{
		{
			TaskDefinitionArn: "arn:aws:ecs:us-east-1:123:task-definition/api:8",
			Source:            RuntimeSourceService,
			Cluster:           "prod",
			Service:           "api",
			DesiredCount:      1,
			RunningCount:      0,
		},
		{
			TaskDefinitionArn: "arn:aws:ecs:us-east-1:123:task-definition/batch:3",
			Source:            RuntimeSourceSchedule,
			ScheduleName:      "nightly",
		},
		{
			TaskDefinitionArn: "arn:aws:ecs:us-east-1:123:task-definition/oneoff:1",
			Source:            RuntimeSourceStandaloneTask,
			TaskArn:           "arn:aws:ecs:us-east-1:123:task/prod/abc",
		},
	}

	got := AnalyzeRuntime(taskDefinitions, signals)

	want := map[string]RuntimeStatus{
		"api:8":     RuntimeServiceDesired,
		"batch:3":   RuntimeScheduled,
		"oneoff:1":  RuntimeStandaloneRecent,
		"dormant:4": RuntimeDefinedOnly,
	}
	for key, wantStatus := range want {
		if got[key].Status != wantStatus {
			t.Fatalf("%s status = %q, want %q", key, got[key].Status, wantStatus)
		}
	}
}

func TestRuntimeAttachesMetadataToInventoryResources(t *testing.T) {
	ref := model.ResourceRef{
		Kind:          "TaskDefinition",
		Provider:      Provider,
		Region:        "us-east-1",
		Name:          "api:7",
		ContainerName: "api",
		ContainerType: "container",
	}
	inventory := &model.Inventory{Resources: []model.ResourceInventory{{
		Resource: ref,
		Images:   []model.ContainerImage{{Name: "api", ContainerType: "container", ImageRef: "example.com/api:1"}},
	}}}
	runtime := map[string]RuntimeMetadata{
		"api:7": {
			Status:   RuntimeObservedRunning,
			Observed: true,
			Evidence: []string{"service api has runningCount 1"},
		},
	}

	AttachRuntimeMetadata(inventory, runtime)

	want := &model.RuntimeMetadata{Status: "observed_running", Observed: true, Evidence: []string{"service api has runningCount 1"}}
	if !reflect.DeepEqual(inventory.Resources[0].Runtime, want) {
		t.Fatalf("Runtime = %#v, want %#v", inventory.Resources[0].Runtime, want)
	}
}
