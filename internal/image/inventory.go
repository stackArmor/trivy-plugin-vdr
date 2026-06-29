package image

import (
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const resourceKind = "Image"

// Collect builds a minimal inventory for standalone image references. Each image
// is represented as one resource so scanner findings can reuse the normal report
// paths without any internet reachability metadata.
func Collect(refs []string) *model.Inventory {
	inventory := &model.Inventory{ContextName: "image"}
	seen := map[string]struct{}{}
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}

		normalized := normalizeImage(ref)
		resource := model.ResourceRef{Kind: resourceKind, Name: ref}
		container := model.ContainerImage{
			Name:            "image",
			ContainerType:   "image",
			ImageRef:        ref,
			NormalizedImage: normalized,
		}
		inventory.Resources = append(inventory.Resources, model.ResourceInventory{
			Resource: resource,
			Images:   []model.ContainerImage{container},
		})

		imageRef := resource
		imageRef.ContainerName = container.Name
		imageRef.ContainerType = container.ContainerType
		inventory.Images = append(inventory.Images, model.ImageInventory{
			ImageRef:        ref,
			NormalizedImage: normalized,
			Resources:       []model.ResourceRef{imageRef},
		})
	}

	sort.Slice(inventory.Resources, func(i, j int) bool {
		return inventory.Resources[i].Resource.Name < inventory.Resources[j].Resource.Name
	})
	sort.Slice(inventory.Images, func(i, j int) bool {
		return inventory.Images[i].ImageRef < inventory.Images[j].ImageRef
	})
	return inventory
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
