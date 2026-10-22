package swarm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

type inspectService struct {
	ID   string `json:"ID"`
	Spec struct {
		Name         string            `json:"Name"`
		Labels       map[string]string `json:"Labels"`
		TaskTemplate struct {
			ContainerSpec struct {
				Image string `json:"Image"`
			} `json:"ContainerSpec"`
			Networks []struct {
				Target string `json:"Target"`
			} `json:"Networks"`
		} `json:"TaskTemplate"`
		Mode struct {
			Replicated *struct{} `json:"Replicated"`
			Global     *struct{} `json:"Global"`
		} `json:"Mode"`
		EndpointSpec struct {
			Ports []inspectPort `json:"Ports"`
		} `json:"EndpointSpec"`
	} `json:"Spec"`
	Endpoint struct {
		Ports []inspectPort `json:"Ports"`
	} `json:"Endpoint"`
}

type inspectPort struct {
	Protocol      string `json:"Protocol"`
	TargetPort    uint32 `json:"TargetPort"`
	PublishedPort uint32 `json:"PublishedPort"`
	PublishMode   string `json:"PublishMode"`
}

type networkEntry struct {
	ID     string `json:"ID"`
	Name   string `json:"Name"`
	Driver string `json:"Driver"`
}

// ParseServices reads `docker service inspect` output. It accepts either the
// raw JSON array, or an object {"services": [...], "networks": [...]} whose
// networks come from `docker network ls --no-trunc --format '{{json .}}'`.
// Service specs reference networks by ID, so only the wrapped form can tell
// that a service is attached to the host network.
func ParseServices(r io.Reader) ([]Service, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var raw []inspectService
	var networks []networkEntry
	trimmed := bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(trimmed, []byte("[")):
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return nil, fmt.Errorf("parse docker service inspect output: %w", err)
		}
	case bytes.HasPrefix(trimmed, []byte("{")):
		var wrapped struct {
			Services []inspectService `json:"services"`
			Networks []networkEntry   `json:"networks"`
		}
		if err := json.Unmarshal(trimmed, &wrapped); err != nil {
			return nil, fmt.Errorf("parse swarm services document: %w", err)
		}
		raw, networks = wrapped.Services, wrapped.Networks
	default:
		return nil, errors.New("swarm services file must be the JSON array printed by docker service inspect, or an object with services and networks")
	}

	networkNames := map[string]string{}
	hostNetworks := map[string]bool{"host": true}
	for _, network := range networks {
		if network.ID == "" {
			continue
		}
		networkNames[network.ID] = network.Name
		if network.Name == "host" || network.Driver == "host" {
			hostNetworks[network.ID] = true
		}
	}

	services := make([]Service, 0, len(raw))
	for _, item := range raw {
		image := strings.TrimSpace(item.Spec.TaskTemplate.ContainerSpec.Image)
		name := strings.TrimSpace(item.Spec.Name)
		if image == "" || name == "" {
			continue
		}
		service := Service{
			ID:     item.ID,
			Name:   name,
			Stack:  strings.TrimSpace(item.Spec.Labels[stackLabel]),
			Image:  image,
			Labels: copyLabels(item.Spec.Labels),
			Mode:   "replicated",
		}
		if service.Stack == "" {
			service.Stack = DefaultStack
		}
		if item.Spec.Mode.Global != nil {
			service.Mode = "global"
		}
		// Endpoint reflects the ports actually allocated; the spec is the
		// fallback for a service whose endpoint has not been reconciled yet.
		ports := item.Endpoint.Ports
		if len(ports) == 0 {
			ports = item.Spec.EndpointSpec.Ports
		}
		for _, port := range ports {
			mode := port.PublishMode
			if mode == "" {
				mode = "ingress"
			}
			service.Ports = append(service.Ports, PublishedPort{
				Protocol:      port.Protocol,
				TargetPort:    port.TargetPort,
				PublishedPort: port.PublishedPort,
				PublishMode:   mode,
			})
		}
		for _, network := range item.Spec.TaskTemplate.Networks {
			if hostNetworks[network.Target] {
				service.HostNetwork = true
			}
			name := network.Target
			if resolved := networkNames[network.Target]; resolved != "" {
				name = resolved
			}
			service.Networks = append(service.Networks, name)
		}
		services = append(services, service)
	}
	return services, nil
}

// BuildInventory turns services into one resource per service, with the stack
// as its namespace. A service runs a single container spec, so the container
// carries the service name.
func BuildInventory(contextName string, services []Service) *model.Inventory {
	inventory := &model.Inventory{ContextName: contextName}
	images := map[string]*model.ImageInventory{}
	for _, service := range services {
		resource := model.ResourceRef{
			APIVersion: "swarm.docker.com/v1",
			Kind:       "Service",
			Provider:   Provider,
			Namespace:  service.Stack,
			Name:       service.Name,
			UID:        service.ID,
		}
		resource.CanonicalID = serviceCanonicalID(contextName, service.Name)
		resource.DisplayID = resource.CanonicalID

		normalized := normalizeImage(service.Image)
		inventory.Resources = append(inventory.Resources, model.ResourceInventory{
			Resource: resource,
			Labels:   copyLabels(service.Labels),
			ProviderMetadata: map[string]string{
				"swarm.mode": service.Mode,
			},
			Images: []model.ContainerImage{{
				Name:            service.Name,
				ContainerType:   "container",
				ImageRef:        service.Image,
				NormalizedImage: normalized,
			}},
		})

		ref := ContainerRef(contextName, service)
		image := images[service.Image]
		if image == nil {
			image = &model.ImageInventory{ImageRef: service.Image, NormalizedImage: normalized}
			images[service.Image] = image
		}
		image.Resources = append(image.Resources, ref)
	}

	sort.Slice(inventory.Resources, func(i, j int) bool {
		return refLess(inventory.Resources[i].Resource, inventory.Resources[j].Resource)
	})
	for _, image := range images {
		sort.Slice(image.Resources, func(i, j int) bool { return refLess(image.Resources[i], image.Resources[j]) })
		inventory.Images = append(inventory.Images, *image)
	}
	sort.Slice(inventory.Images, func(i, j int) bool { return inventory.Images[i].ImageRef < inventory.Images[j].ImageRef })
	return inventory
}

// ContainerRef is the container-level reference a service's findings and
// exposure are keyed by.
func ContainerRef(contextName string, service Service) model.ResourceRef {
	return model.ResourceRef{
		APIVersion:    "swarm.docker.com/v1",
		Kind:          "Service",
		Provider:      Provider,
		Namespace:     service.Stack,
		Name:          service.Name,
		UID:           service.ID,
		ContainerName: service.Name,
		ContainerType: "container",
		CanonicalID:   serviceCanonicalID(contextName, service.Name) + "/container/" + url.PathEscape(service.Name),
		DisplayID:     serviceCanonicalID(contextName, service.Name) + "/container/" + url.PathEscape(service.Name),
	}
}

func serviceCanonicalID(contextName, name string) string {
	return fmt.Sprintf("docker-swarm://%s/service/%s", url.PathEscape(contextName), url.PathEscape(name))
}

func refLess(a, b model.ResourceRef) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	return a.Name < b.Name
}

func normalizeImage(image string) string {
	if ref, err := reference.ParseAnyReference(image); err == nil {
		if named, ok := ref.(reference.Named); ok {
			return reference.FamiliarString(reference.TrimNamed(named))
		}
	}
	if before, _, ok := strings.Cut(image, "@"); ok {
		image = before
	}
	if lastColon := strings.LastIndex(image, ":"); lastColon > strings.LastIndex(image, "/") {
		return image[:lastColon]
	}
	return image
}

func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	copied := make(map[string]string, len(labels))
	for key, value := range labels {
		copied[key] = value
	}
	return copied
}
