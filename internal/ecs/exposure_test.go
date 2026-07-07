package ecs

import (
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestExposureMarksInternetFacingLoadBalancedServicePublic(t *testing.T) {
	ref := ecsContainerRef("api:7", "api")
	inventory := ecsInventory(ref)
	runtime := map[string]RuntimeMetadata{"api:7": {Status: RuntimeServiceDesired}}
	graph := ExposureGraph{
		Services: []ECSServiceExposure{{
			Name:               "api",
			Cluster:            "prod",
			TaskDefinitionName: "api:7",
			TargetGroups:       []string{"tg-api"},
		}},
		LoadBalancers: []LoadBalancerExposure{{
			Name:        "app-public",
			Scheme:      "internet-facing",
			TargetGroup: "tg-api",
		}},
	}

	got := AnalyzeExposureFromGraph(inventory, runtime, graph)

	exposure := got[ref]
	if !exposure.InternetAccessible {
		t.Fatalf("exposure = %#v, want internet accessible", exposure)
	}
	if exposure.RouteKind != "LoadBalancer" || exposure.RouteName != "app-public" {
		t.Fatalf("route = %s/%s", exposure.RouteKind, exposure.RouteName)
	}
}

func TestExposureDoesNotMarkInternalLoadBalancerOrDefinedOnlyPublic(t *testing.T) {
	ref := ecsContainerRef("api:7", "api")
	inventory := ecsInventory(ref)
	graph := ExposureGraph{
		Services: []ECSServiceExposure{{
			Name:               "api",
			Cluster:            "prod",
			TaskDefinitionName: "api:7",
			TargetGroups:       []string{"tg-api"},
		}},
		LoadBalancers: []LoadBalancerExposure{{
			Name:        "app-internal",
			Scheme:      "internal",
			TargetGroup: "tg-api",
		}},
	}

	got := AnalyzeExposureFromGraph(inventory, map[string]RuntimeMetadata{"api:7": {Status: RuntimeDefinedOnly}}, graph)

	exposure := got[ref]
	if exposure.InternetAccessible {
		t.Fatalf("exposure = %#v, want not internet accessible", exposure)
	}
}

func TestExposureMarksPublicTaskENIWithOpenIngressPublic(t *testing.T) {
	ref := ecsContainerRef("api:7", "api")
	inventory := ecsInventory(ref)
	runtime := map[string]RuntimeMetadata{"api:7": {Status: RuntimeObservedRunning, Observed: true}}
	graph := ExposureGraph{
		Tasks: []RunningTaskExposure{{
			TaskArn:            "arn:aws:ecs:us-east-1:123:task/prod/abc",
			TaskDefinitionName: "api:7",
			ENI:                "eni-123",
			PublicIP:           "203.0.113.10",
			SecurityGroups:     []string{"sg-123"},
		}},
		SecurityGroups: []SecurityGroupExposure{{
			ID: "sg-123",
			Ingress: []IngressRule{{
				CIDR:     "0.0.0.0/0",
				Protocol: "tcp",
				FromPort: 443,
				ToPort:   443,
			}},
		}},
		Ports: map[string][]PortMapping{
			"api:7/api": {{ContainerPort: 443, Protocol: "tcp"}},
		},
	}

	got := AnalyzeExposureFromGraph(inventory, runtime, graph)

	exposure := got[ref]
	if !exposure.InternetAccessible {
		t.Fatalf("exposure = %#v, want public task ENI exposure", exposure)
	}
	if exposure.RouteKind != "TaskENI" || exposure.RouteName != "eni-123" {
		t.Fatalf("route = %s/%s", exposure.RouteKind, exposure.RouteName)
	}
}

func ecsContainerRef(taskDefinition, container string) model.ResourceRef {
	return model.ResourceRef{
		APIVersion:    "ecs.amazonaws.com/v1",
		Kind:          "TaskDefinition",
		Provider:      Provider,
		Region:        "us-east-1",
		Name:          taskDefinition,
		ContainerName: container,
		ContainerType: "container",
	}
}

func ecsInventory(ref model.ResourceRef) *model.Inventory {
	base := ref
	base.ContainerName = ""
	base.ContainerType = ""
	return &model.Inventory{Resources: []model.ResourceInventory{{
		Resource: base,
		Images: []model.ContainerImage{{
			Name:          ref.ContainerName,
			ContainerType: ref.ContainerType,
			ImageRef:      "example.com/api:1",
		}},
	}}}
}
