package cloudrun

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func (c Collector) Collect(ctx context.Context, opts Options) (*model.Inventory, error) {
	inventory, _, _, err := c.CollectResources(ctx, opts)
	return inventory, err
}

func (c Collector) CollectResources(ctx context.Context, opts Options) (*model.Inventory, []Service, []Job, error) {
	if c.Client == nil {
		return nil, nil, nil, errors.New("cloudrun collector requires a client")
	}
	if strings.TrimSpace(opts.Project) == "" {
		return nil, nil, nil, errors.New("cloudrun project is required")
	}
	if len(opts.Regions) == 0 {
		return nil, nil, nil, errors.New("cloudrun region is required")
	}

	builder := inventoryBuilder{
		inventory: &model.Inventory{ContextName: "cloudrun/" + opts.Project},
		images:    map[string]*model.ImageInventory{},
	}
	if labelClient, ok := c.Client.(ProjectLabelClient); ok {
		labels, err := labelClient.GetProjectLabels(ctx, opts.Project)
		if err != nil {
			builder.inventory.Warnings = append(builder.inventory.Warnings, fmt.Sprintf("cloudrun project labels for %s not read (%v); PAIN scoring uses built-in defaults unless resource labels are present", opts.Project, err))
		} else if len(labels) > 0 {
			builder.inventory.Namespaces = map[string]map[string]string{ProjectLabelScope(opts.Project): copyStringMap(labels)}
		}
	}
	var allServices []Service
	var allJobs []Job
	for _, region := range opts.Regions {
		region = strings.TrimSpace(region)
		if region == "" {
			return nil, nil, nil, errors.New("cloudrun region entries cannot be empty")
		}
		services, err := c.Client.ListServices(ctx, opts.Project, region)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("list cloudrun services in %s: %w", region, err)
		}
		for _, service := range services {
			builder.addService(service)
		}
		allServices = append(allServices, services...)
		jobs, err := c.Client.ListJobs(ctx, opts.Project, region)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("list cloudrun jobs in %s: %w", region, err)
		}
		for _, job := range jobs {
			builder.addJob(job)
		}
		allJobs = append(allJobs, jobs...)
	}
	return builder.finish(), allServices, allJobs, nil
}

func ProjectLabelScope(project string) string {
	return "cloudrun/" + project
}

type inventoryBuilder struct {
	inventory *model.Inventory
	images    map[string]*model.ImageInventory
}

func (b *inventoryBuilder) addService(service Service) {
	ref := model.ResourceRef{
		APIVersion: "run.googleapis.com/v1",
		Kind:       "Service",
		Provider:   Provider,
		Project:    service.Project,
		Region:     service.Region,
		Name:       service.Name,
	}
	b.addResource(ref, service.Labels, service.Containers)
}

func (b *inventoryBuilder) addJob(job Job) {
	ref := model.ResourceRef{
		APIVersion: "run.googleapis.com/v1",
		Kind:       "Job",
		Provider:   Provider,
		Project:    job.Project,
		Region:     job.Region,
		Name:       job.Name,
	}
	b.addResource(ref, job.Labels, job.Containers)
}

func (b *inventoryBuilder) addResource(resource model.ResourceRef, labels map[string]string, containers []Container) {
	resourceInventory := model.ResourceInventory{Resource: resource, Labels: copyStringMap(labels)}
	for _, container := range containers {
		b.addContainer(&resourceInventory, resource, container)
	}
	if len(resourceInventory.Images) > 0 {
		b.inventory.Resources = append(b.inventory.Resources, resourceInventory)
	}
}

func (b *inventoryBuilder) addContainer(resourceInventory *model.ResourceInventory, resource model.ResourceRef, container Container) {
	if container.Image == "" {
		return
	}
	name := container.Name
	if name == "" {
		name = "container"
	}
	normalized := normalizeImage(container.Image)
	resourceInventory.Images = append(resourceInventory.Images, model.ContainerImage{
		Name:            name,
		ContainerType:   "container",
		ImageRef:        container.Image,
		NormalizedImage: normalized,
	})

	ref := resource
	ref.ContainerName = name
	ref.ContainerType = "container"
	image := b.images[container.Image]
	if image == nil {
		image = &model.ImageInventory{
			ImageRef:        container.Image,
			NormalizedImage: normalized,
		}
		b.images[container.Image] = image
	}
	image.Resources = append(image.Resources, ref)
}

func (b *inventoryBuilder) finish() *model.Inventory {
	for _, image := range b.images {
		sort.Slice(image.Resources, func(i, j int) bool {
			return resourceLess(image.Resources[i], image.Resources[j])
		})
		b.inventory.Images = append(b.inventory.Images, *image)
	}
	sort.Slice(b.inventory.Images, func(i, j int) bool {
		return b.inventory.Images[i].ImageRef < b.inventory.Images[j].ImageRef
	})
	sort.Slice(b.inventory.Resources, func(i, j int) bool {
		return resourceLess(b.inventory.Resources[i].Resource, b.inventory.Resources[j].Resource)
	})
	return b.inventory
}

func resourceLess(a, b model.ResourceRef) bool {
	left := []string{a.Provider, a.Project, a.Region, a.Namespace, a.Kind, a.Name, a.ContainerType, a.ContainerName}
	right := []string{b.Provider, b.Project, b.Region, b.Namespace, b.Kind, b.Name, b.ContainerType, b.ContainerName}
	for i := range left {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return false
}

func normalizeImage(image string) string {
	ref, err := reference.ParseAnyReference(image)
	if err == nil {
		if named, ok := ref.(reference.Named); ok {
			return reference.FamiliarString(reference.TrimNamed(named))
		}
	}

	if beforeDigest, _, ok := strings.Cut(image, "@"); ok {
		image = beforeDigest
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon > lastSlash {
		return image[:lastColon]
	}
	return image
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	copied := make(map[string]string, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}
