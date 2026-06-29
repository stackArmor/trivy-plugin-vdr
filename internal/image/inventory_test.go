package image

import "testing"

func TestCollectBuildsInventoryForImageRefs(t *testing.T) {
	inventory := Collect([]string{"gcr.io/example/app:v1", "nginx:1.25"})

	if inventory.ContextName != "image" {
		t.Fatalf("ContextName = %q, want image", inventory.ContextName)
	}
	if len(inventory.Resources) != 2 {
		t.Fatalf("Resources = %d, want 2", len(inventory.Resources))
	}
	if len(inventory.Images) != 2 {
		t.Fatalf("Images = %d, want 2", len(inventory.Images))
	}
	firstResource := inventory.Resources[0]
	if firstResource.Resource.Kind != "Image" || firstResource.Resource.Name != "gcr.io/example/app:v1" {
		t.Fatalf("first resource = %#v", firstResource.Resource)
	}
	if firstResource.Images[0].ImageRef != "gcr.io/example/app:v1" {
		t.Fatalf("first resource image = %q", firstResource.Images[0].ImageRef)
	}
	wantImageRef := firstResource.Resource
	wantImageRef.ContainerName = "image"
	wantImageRef.ContainerType = "image"
	if inventory.Images[0].Resources[0] != wantImageRef {
		t.Fatalf("image resource ref = %#v, want %#v", inventory.Images[0].Resources[0], wantImageRef)
	}
}

func TestCollectDeduplicatesImages(t *testing.T) {
	inventory := Collect([]string{"nginx:1.25", "nginx:1.25"})

	if len(inventory.Resources) != 1 {
		t.Fatalf("Resources = %d, want 1", len(inventory.Resources))
	}
	if len(inventory.Images) != 1 {
		t.Fatalf("Images = %d, want 1", len(inventory.Images))
	}
}
