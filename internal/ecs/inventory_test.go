package ecs

import (
	"context"
	"reflect"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestInventoryCollectsTaskDefinitions(t *testing.T) {
	client := &fakeInventoryClient{
		taskDefinitions: map[string][]TaskDefinition{
			"us-gov-west-1": {{
				Region:   "us-gov-west-1",
				Arn:      "arn:aws-us-gov:ecs:us-gov-west-1:123:task-definition/api:7",
				Family:   "api",
				Revision: 7,
				Status:   "ACTIVE",
				Containers: []ContainerDefinition{{
					Name:                           "api",
					Image:                          "123.dkr.ecr.us-gov-west-1.amazonaws.com/api:1",
					RepositoryCredentialsSecretARN: "arn:aws-us-gov:secretsmanager:us-gov-west-1:123:secret:dockerhub",
				}},
			}},
		},
	}

	got, err := (Collector{Client: client}).Collect(context.Background(), Options{Regions: []string{"us-gov-west-1"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got.ContextName != "ecs" {
		t.Fatalf("ContextName = %q, want ecs", got.ContextName)
	}
	if len(got.Resources) != 1 {
		t.Fatalf("resources = %d, want 1: %#v", len(got.Resources), got.Resources)
	}
	if len(got.Images) != 1 {
		t.Fatalf("images = %d, want 1: %#v", len(got.Images), got.Images)
	}

	wantRef := model.ResourceRef{
		APIVersion:    "ecs.amazonaws.com/v1",
		Kind:          "TaskDefinition",
		Provider:      "aws-ecs",
		Region:        "us-gov-west-1",
		Name:          "api:7",
		UID:           "arn:aws-us-gov:ecs:us-gov-west-1:123:task-definition/api:7",
		CanonicalID:   "aws-ecs://us-gov-west-1/task-definition/api:7/container/api",
		DisplayID:     "aws-ecs://us-gov-west-1/task-definition/api:7/container/api",
		ContainerName: "api",
		ContainerType: "container",
	}
	if !reflect.DeepEqual(got.Images[0].Resources, []model.ResourceRef{wantRef}) {
		t.Fatalf("image resources = %#v, want %#v", got.Images[0].Resources, []model.ResourceRef{wantRef})
	}
	if got.Images[0].NormalizedImage != "123.dkr.ecr.us-gov-west-1.amazonaws.com/api" {
		t.Fatalf("NormalizedImage = %q", got.Images[0].NormalizedImage)
	}
}

func TestInventoryDeduplicatesSharedTaskDefinitionImages(t *testing.T) {
	client := &fakeInventoryClient{
		taskDefinitions: map[string][]TaskDefinition{
			"us-east-1": {
				{
					Region:   "us-east-1",
					Arn:      "arn:aws:ecs:us-east-1:123:task-definition/api:7",
					Family:   "api",
					Revision: 7,
					Status:   "ACTIVE",
					Containers: []ContainerDefinition{{
						Name:  "api",
						Image: "example.com/app:1",
					}},
				},
				{
					Region:   "us-east-1",
					Arn:      "arn:aws:ecs:us-east-1:123:task-definition/worker:2",
					Family:   "worker",
					Revision: 2,
					Status:   "ACTIVE",
					Containers: []ContainerDefinition{{
						Name:  "worker",
						Image: "example.com/app:1",
					}},
				},
			},
		},
	}

	got, err := (Collector{Client: client}).Collect(context.Background(), Options{Regions: []string{"us-east-1"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(got.Images) != 1 {
		t.Fatalf("images = %d, want one deduplicated image: %#v", len(got.Images), got.Images)
	}
	if len(got.Images[0].Resources) != 2 {
		t.Fatalf("image resources = %#v, want two refs", got.Images[0].Resources)
	}
}

type fakeInventoryClient struct {
	taskDefinitions map[string][]TaskDefinition
}

func (f *fakeInventoryClient) ListTaskDefinitions(ctx context.Context, region string) ([]TaskDefinition, error) {
	return append([]TaskDefinition(nil), f.taskDefinitions[region]...), nil
}
