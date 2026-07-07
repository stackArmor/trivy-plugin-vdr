package ecs

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func (c Collector) Collect(ctx context.Context, opts Options) (*model.Inventory, error) {
	inventory, _, err := c.CollectResources(ctx, opts)
	return inventory, err
}

func (c Collector) CollectResources(ctx context.Context, opts Options) (*model.Inventory, []TaskDefinition, error) {
	if c.Client == nil {
		return nil, nil, errors.New("ecs collector requires a client")
	}
	if len(opts.Regions) == 0 {
		return nil, nil, errors.New("ecs region is required")
	}

	var allTaskDefinitions []TaskDefinition
	var collectedTaskDefinitions []TaskDefinition
	for _, region := range opts.Regions {
		region = strings.TrimSpace(region)
		if region == "" {
			return nil, nil, errors.New("ecs region entries cannot be empty")
		}
		taskDefinitions, err := c.Client.ListTaskDefinitions(ctx, region)
		if err != nil {
			return nil, nil, fmt.Errorf("list ecs task definitions in %s: %w", region, err)
		}
		for _, taskDefinition := range taskDefinitions {
			if taskDefinition.Region == "" {
				taskDefinition.Region = region
			}
			collectedTaskDefinitions = append(collectedTaskDefinitions, taskDefinition)
		}
		allTaskDefinitions = append(allTaskDefinitions, taskDefinitions...)
	}
	return buildInventoryFromTaskDefinitions(collectedTaskDefinitions), allTaskDefinitions, nil
}

func buildInventoryFromTaskDefinitions(taskDefinitions []TaskDefinition) *model.Inventory {
	builder := inventoryBuilder{
		inventory: &model.Inventory{ContextName: "ecs"},
		images:    map[string]*model.ImageInventory{},
	}
	for _, taskDefinition := range taskDefinitions {
		builder.addTaskDefinition(taskDefinition)
	}
	return builder.finish()
}

type inventoryBuilder struct {
	inventory *model.Inventory
	images    map[string]*model.ImageInventory
}

func (b *inventoryBuilder) addTaskDefinition(taskDefinition TaskDefinition) {
	name := taskDefinitionName(taskDefinition)
	resource := model.ResourceRef{
		APIVersion: "ecs.amazonaws.com/v1",
		Kind:       "TaskDefinition",
		Provider:   Provider,
		Region:     taskDefinition.Region,
		Name:       name,
		UID:        taskDefinition.Arn,
	}
	resource.CanonicalID = ecsBaseCanonicalID(resource)
	resource.DisplayID = resource.CanonicalID

	resourceInventory := model.ResourceInventory{
		Resource:         resource,
		ProviderMetadata: taskDefinitionProviderMetadata(taskDefinition),
	}
	for _, container := range taskDefinition.Containers {
		b.addContainer(&resourceInventory, resource, container)
	}
	if len(resourceInventory.Images) > 0 {
		b.inventory.Resources = append(b.inventory.Resources, resourceInventory)
	}
}

func (b *inventoryBuilder) addContainer(resourceInventory *model.ResourceInventory, resource model.ResourceRef, container ContainerDefinition) {
	if container.Image == "" {
		return
	}
	name := strings.TrimSpace(container.Name)
	if name == "" {
		name = "container"
	}
	normalized := normalizeImage(container.Image)
	resourceInventory.Images = append(resourceInventory.Images, model.ContainerImage{
		Name:            name,
		ContainerType:   "container",
		ImageRef:        container.Image,
		NormalizedImage: normalized,
		Security:        containerSecurity(container),
	})

	ref := resource
	ref.ContainerName = name
	ref.ContainerType = "container"
	ref.CanonicalID = ecsContainerCanonicalID(resource, name)
	ref.DisplayID = ref.CanonicalID

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

func taskDefinitionProviderMetadata(taskDefinition TaskDefinition) map[string]string {
	metadata := map[string]string{}
	if taskDefinition.ExecutionRoleArn != "" {
		metadata["ecs.executionRoleArn"] = taskDefinition.ExecutionRoleArn
	}
	if taskDefinition.TaskRoleArn != "" {
		metadata["ecs.taskRoleArn"] = taskDefinition.TaskRoleArn
	}
	if taskDefinition.NetworkMode != "" {
		metadata["ecs.networkMode"] = taskDefinition.NetworkMode
	}
	if len(taskDefinition.RequiresCompatibilities) > 0 {
		compatibilities := append([]string(nil), taskDefinition.RequiresCompatibilities...)
		sort.Strings(compatibilities)
		metadata["ecs.requiresCompatibilities"] = strings.Join(compatibilities, ",")
	}
	for _, container := range taskDefinition.Containers {
		name := strings.TrimSpace(container.Name)
		if name == "" {
			name = "container"
		}
		prefix := "ecs.container." + name + "."
		if container.User != "" {
			metadata[prefix+"user"] = container.User
		}
		if container.InitProcessEnabled != nil {
			metadata[prefix+"init"] = strconv.FormatBool(*container.InitProcessEnabled)
		}
		if container.LogDriver != "" {
			metadata[prefix+"logDriver"] = container.LogDriver
		}
		if len(container.Secrets) > 0 {
			metadata[prefix+"secrets"] = strconv.Itoa(len(container.Secrets))
		}
		if len(container.EnvironmentFiles) > 0 {
			metadata[prefix+"envFiles"] = strconv.Itoa(len(container.EnvironmentFiles))
		}
	}
	return metadata
}

func containerSecurity(container ContainerDefinition) *model.ContainerSecurity {
	if !container.Privileged && !container.ReadonlyRootFilesystem && len(container.CapabilitiesAdd) == 0 && len(container.CapabilitiesDrop) == 0 {
		return nil
	}
	privileged := container.Privileged
	readonly := container.ReadonlyRootFilesystem
	return &model.ContainerSecurity{
		Privileged:             &privileged,
		ReadOnlyRootFilesystem: &readonly,
		CapabilitiesAdd:        append([]string(nil), container.CapabilitiesAdd...),
		CapabilitiesDrop:       append([]string(nil), container.CapabilitiesDrop...),
	}
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

func taskDefinitionName(taskDefinition TaskDefinition) string {
	if taskDefinition.Family == "" {
		return taskDefinition.Arn
	}
	return fmt.Sprintf("%s:%d", taskDefinition.Family, taskDefinition.Revision)
}

func ecsBaseCanonicalID(ref model.ResourceRef) string {
	return fmt.Sprintf("aws-ecs://%s/task-definition/%s",
		url.PathEscape(ref.Region),
		url.PathEscape(ref.Name),
	)
}

func ecsContainerCanonicalID(ref model.ResourceRef, containerName string) string {
	return ecsBaseCanonicalID(ref) + "/container/" + url.PathEscape(containerName)
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
