package cloudrun

import (
	"context"
	"reflect"
	"testing"
)

func TestCollectInventoriesServicesAndJobs(t *testing.T) {
	client := &fakeInventoryClient{
		services: map[string][]Service{
			"us-east4": {{
				Project: "armory-gss-prod",
				Region:  "us-east4",
				Name:    "peregrine",
				Labels:  map[string]string{"vdr.fedramp.io/asset-archetype": "app-tier"},
				Containers: []Container{
					{Name: "gateway", Image: "us-east4-docker.pkg.dev/p/peregrine/gateway:1"},
					{Name: "worker", Image: "us-east4-docker.pkg.dev/p/peregrine/worker:2"},
				},
			}},
		},
		jobs: map[string][]Job{
			"us-east4": {{
				Project: "armory-gss-prod",
				Region:  "us-east4",
				Name:    "asa-cloudrun-job",
				Containers: []Container{
					{Name: "asa", Image: "us-east4-docker.pkg.dev/p/asa/asa:latest"},
				},
			}},
		},
	}
	collector := Collector{Client: client}

	got, err := collector.Collect(context.Background(), Options{Project: "armory-gss-prod", Regions: []string{"us-east4"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got.ContextName != "cloudrun/armory-gss-prod" {
		t.Fatalf("ContextName = %q", got.ContextName)
	}
	if len(got.Resources) != 2 {
		t.Fatalf("resources = %d, want 2: %#v", len(got.Resources), got.Resources)
	}
	if len(got.Images) != 3 {
		t.Fatalf("images = %d, want 3: %#v", len(got.Images), got.Images)
	}
	wantKinds := []string{got.Resources[0].Resource.Kind, got.Resources[1].Resource.Kind}
	if !reflect.DeepEqual(wantKinds, []string{"Job", "Service"}) {
		t.Fatalf("resource order/kinds = %#v", wantKinds)
	}
}

func TestCollectDeduplicatesSharedImages(t *testing.T) {
	client := &fakeInventoryClient{
		services: map[string][]Service{
			"us-east4": {{
				Project:    "p",
				Region:     "us-east4",
				Name:       "api",
				Containers: []Container{{Name: "app", Image: "example.com/app:1"}},
			}},
		},
		jobs: map[string][]Job{
			"us-east4": {{
				Project:    "p",
				Region:     "us-east4",
				Name:       "batch",
				Containers: []Container{{Name: "app", Image: "example.com/app:1"}},
			}},
		},
	}

	got, err := (Collector{Client: client}).Collect(context.Background(), Options{Project: "p", Regions: []string{"us-east4"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(got.Images) != 1 {
		t.Fatalf("images = %d, want one deduplicated image: %#v", len(got.Images), got.Images)
	}
	if len(got.Images[0].Resources) != 2 {
		t.Fatalf("image resources = %#v, want service and job refs", got.Images[0].Resources)
	}
}

func TestCollectStoresProjectLabelsForScoringFallback(t *testing.T) {
	client := &fakeInventoryClient{
		projectLabels: map[string]string{
			"vdr.fedramp.io/asset-archetype": "data-sensitive",
			"vdr.fedramp.io/multi-agency":    "true",
			"vdr.fedramp.io/class":           "D",
		},
		services: map[string][]Service{
			"us-east4": {{
				Project:    "p",
				Region:     "us-east4",
				Name:       "api",
				Containers: []Container{{Name: "app", Image: "example.com/app:1"}},
			}},
		},
	}

	got, err := (Collector{Client: client}).Collect(context.Background(), Options{Project: "p", Regions: []string{"us-east4"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	labels := got.Namespaces["cloudrun/p"]
	if !reflect.DeepEqual(labels, client.projectLabels) {
		t.Fatalf("project fallback labels = %#v, want %#v", labels, client.projectLabels)
	}
}

type fakeInventoryClient struct {
	services      map[string][]Service
	jobs          map[string][]Job
	projectLabels map[string]string
}

func (f *fakeInventoryClient) ListServices(ctx context.Context, project, region string) ([]Service, error) {
	return append([]Service(nil), f.services[region]...), nil
}

func (f *fakeInventoryClient) ListJobs(ctx context.Context, project, region string) ([]Job, error) {
	return append([]Job(nil), f.jobs[region]...), nil
}

func (f *fakeInventoryClient) GetProjectLabels(ctx context.Context, project string) (map[string]string, error) {
	return copyStringMap(f.projectLabels), nil
}
