package cloudrun

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const googleBaseImageUpdateRuntime = "run.googleapis.com/linux-base-image-update"

var googleBaseImageUpdateSkipDirs = []string{"/cnb", "layers/sbom"}

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
	kind := serviceKind(service)
	ref := model.ResourceRef{
		APIVersion: "run.googleapis.com/v1",
		Kind:       kind,
		Provider:   Provider,
		Project:    service.Project,
		Region:     service.Region,
		Name:       service.Name,
		UID:        cloudRunUID(service.Project, service.Region, kind, service.Name),
	}
	ref.CanonicalID = cloudRunBaseCanonicalID(ref)
	ref.DisplayID = ref.CanonicalID
	b.addResource(ref, service.Labels, service.Containers, skipDirsForRuntime(service.RuntimeClassName), service.ExecutionEnvironment)
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
	ref.UID = cloudRunUID(job.Project, job.Region, ref.Kind, job.Name)
	ref.CanonicalID = cloudRunBaseCanonicalID(ref)
	ref.DisplayID = ref.CanonicalID
	b.addResource(ref, job.Labels, job.Containers, nil, job.ExecutionEnvironment)
}

// cloudRunContainerSecurity reports the security posture Cloud Run enforces on
// every container: never privileged, no capability changes, and a writable
// in-memory root filesystem. Sandbox is set when the execution environment is
// explicit: gen1 runs under the gVisor user-space kernel, gen2 in a microVM.
func cloudRunContainerSecurity(executionEnvironment string) *model.ContainerSecurity {
	privileged := false
	readOnly := false
	security := &model.ContainerSecurity{
		Privileged:             &privileged,
		ReadOnlyRootFilesystem: &readOnly,
	}
	switch executionEnvironment {
	case "gen1":
		security.Sandbox = "gVisor"
	case "gen2":
		security.Sandbox = "microVM"
	}
	return security
}

func (b *inventoryBuilder) addResource(resource model.ResourceRef, labels map[string]string, containers []Container, skipDirs []string, executionEnvironment string) {
	resourceInventory := model.ResourceInventory{Resource: resource, Labels: copyStringMap(labels)}
	singleContainer := len(containers) == 1
	for _, container := range containers {
		b.addContainer(&resourceInventory, resource, container, skipDirs, singleContainer, executionEnvironment)
	}
	if len(resourceInventory.Images) > 0 {
		b.inventory.Resources = append(b.inventory.Resources, resourceInventory)
	}
}

func (b *inventoryBuilder) addContainer(resourceInventory *model.ResourceInventory, resource model.ResourceRef, container Container, skipDirs []string, singleContainer bool, executionEnvironment string) {
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
		Security:        cloudRunContainerSecurity(executionEnvironment),
	})

	ref := resource
	ref.ContainerName = name
	ref.ContainerType = "container"
	ref.CanonicalID = cloudRunContainerCanonicalID(resource, name)
	ref.DisplayID = ref.CanonicalID
	if resource.Kind == "Function" && singleContainer {
		ref.DisplayID = resource.DisplayID
	}
	image := b.images[container.Image]
	if image == nil {
		image = &model.ImageInventory{
			ImageRef:        container.Image,
			NormalizedImage: normalized,
		}
		b.images[container.Image] = image
	}
	image.Resources = append(image.Resources, ref)
	image.SkipDirs = mergeStrings(image.SkipDirs, skipDirs)
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

func cloudRunUID(project, region, kind, name string) string {
	resource := "services"
	if kind == "Job" {
		resource = "jobs"
	}
	return fmt.Sprintf("projects/%s/locations/%s/%s/%s", project, region, resource, name)
}

func cloudRunBaseCanonicalID(ref model.ResourceRef) string {
	return fmt.Sprintf("gcp-cloud-run://%s/%s/%s/%s",
		url.PathEscape(ref.Project),
		url.PathEscape(ref.Region),
		strings.ToLower(ref.Kind),
		url.PathEscape(ref.Name),
	)
}

func cloudRunContainerCanonicalID(ref model.ResourceRef, containerName string) string {
	return cloudRunBaseCanonicalID(ref) + "/container/" + url.PathEscape(containerName)
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

func serviceKind(service Service) string {
	if isCloudFunctionService(service) {
		return "Function"
	}
	return "Service"
}

func isCloudFunctionService(service Service) bool {
	if service.Annotations["cloudfunctions.googleapis.com/function-id"] != "" {
		return true
	}
	if service.Labels["goog-managed-by"] == "cloudfunctions" {
		return true
	}
	return service.Labels["goog-cloudfunctions-runtime"] != ""
}

func skipDirsForRuntime(runtimeClassName string) []string {
	if runtimeClassName != googleBaseImageUpdateRuntime {
		return nil
	}
	return append([]string(nil), googleBaseImageUpdateSkipDirs...)
}

func mergeStrings(existing, added []string) []string {
	if len(added) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(added))
	result := append([]string(nil), existing...)
	for _, value := range result {
		seen[value] = struct{}{}
	}
	for _, value := range added {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
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
