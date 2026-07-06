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

func TestCollectAddsCloudRunCanonicalIDs(t *testing.T) {
	client := &fakeInventoryClient{
		services: map[string][]Service{
			"us-east4": {{
				Project: "p",
				Region:  "us-east4",
				Name:    "api",
				Containers: []Container{
					{Name: "gateway", Image: "example.com/gateway:1"},
					{Name: "worker", Image: "example.com/worker:1"},
				},
			}},
		},
	}

	got, err := (Collector{Client: client}).Collect(context.Background(), Options{Project: "p", Regions: []string{"us-east4"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	resource := got.Resources[0].Resource
	if resource.UID != "projects/p/locations/us-east4/services/api" {
		t.Fatalf("resource UID = %q", resource.UID)
	}
	if resource.CanonicalID != "gcp-cloud-run://p/us-east4/service/api" {
		t.Fatalf("resource CanonicalID = %q", resource.CanonicalID)
	}
	if resource.DisplayID != "gcp-cloud-run://p/us-east4/service/api" {
		t.Fatalf("resource DisplayID = %q", resource.DisplayID)
	}

	for _, image := range got.Images {
		if len(image.Resources) != 1 {
			t.Fatalf("image resources = %#v, want one", image.Resources)
		}
		ref := image.Resources[0]
		wantCanonical := "gcp-cloud-run://p/us-east4/service/api/container/" + ref.ContainerName
		if ref.CanonicalID != wantCanonical {
			t.Fatalf("container %s CanonicalID = %q, want %q", ref.ContainerName, ref.CanonicalID, wantCanonical)
		}
		if ref.DisplayID != wantCanonical {
			t.Fatalf("container %s DisplayID = %q, want %q", ref.ContainerName, ref.DisplayID, wantCanonical)
		}
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

func TestCollectAddsGoogleBaseImageUpdateSkipDirs(t *testing.T) {
	client := &fakeInventoryClient{
		services: map[string][]Service{
			"us-east4": {{
				Project:          "p",
				Region:           "us-east4",
				Name:             "fn",
				RuntimeClassName: "run.googleapis.com/linux-base-image-update",
				Labels:           map[string]string{"goog-managed-by": "cloudfunctions"},
				Containers:       []Container{{Name: "app", Image: "example.com/fn:1"}},
			}},
		},
	}

	got, err := (Collector{Client: client}).Collect(context.Background(), Options{Project: "p", Regions: []string{"us-east4"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(got.Images) != 1 {
		t.Fatalf("images = %#v, want one image", got.Images)
	}
	if got.Resources[0].Resource.Kind != "Function" {
		t.Fatalf("resource kind = %q, want Function", got.Resources[0].Resource.Kind)
	}
	ref := got.Images[0].Resources[0]
	if ref.UID != "projects/p/locations/us-east4/services/fn" {
		t.Fatalf("function UID = %q", ref.UID)
	}
	if ref.CanonicalID != "gcp-cloud-run://p/us-east4/function/fn/container/app" {
		t.Fatalf("function CanonicalID = %q", ref.CanonicalID)
	}
	if ref.DisplayID != "gcp-cloud-run://p/us-east4/function/fn" {
		t.Fatalf("function DisplayID = %q", ref.DisplayID)
	}
	want := []string{"/cnb", "layers/sbom"}
	if !reflect.DeepEqual(got.Images[0].SkipDirs, want) {
		t.Fatalf("SkipDirs = %#v, want %#v", got.Images[0].SkipDirs, want)
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
