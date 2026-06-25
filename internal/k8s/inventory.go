package k8s

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/matthewvenne/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Options struct {
	Namespaces            []string
	AllNamespaces         bool
	IncludeZeroDaemonSets bool
}

type Collector struct {
	Client      kubernetes.Interface
	ContextName string
}

func NewForCurrentContext() (*Collector, string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	rawConfig, err := loadingRules.Load()
	if err != nil {
		return nil, "", err
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, "", err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, "", err
	}

	contextName := rawConfig.CurrentContext
	return &Collector{Client: client, ContextName: contextName}, contextName, nil
}

func (c *Collector) Collect(ctx context.Context, opts Options) (*model.Inventory, error) {
	if c == nil || c.Client == nil {
		return nil, errors.New("kubernetes collector requires a client")
	}

	builder := inventoryBuilder{
		inventory: &model.Inventory{ContextName: c.ContextName},
		images:    map[string]*model.ImageInventory{},
	}

	namespaces, err := namespacesForCollection(opts)
	if err != nil {
		return nil, err
	}

	for _, namespace := range namespaces {
		if err := c.collectPods(ctx, namespace, &builder); err != nil {
			return nil, err
		}
		if err := c.collectDeployments(ctx, namespace, &builder); err != nil {
			return nil, err
		}
		if err := c.collectStatefulSets(ctx, namespace, &builder); err != nil {
			return nil, err
		}
		if err := c.collectDaemonSets(ctx, namespace, opts.IncludeZeroDaemonSets, &builder); err != nil {
			return nil, err
		}
		if err := c.collectJobs(ctx, namespace, &builder); err != nil {
			return nil, err
		}
		if err := c.collectCronJobs(ctx, namespace, &builder); err != nil {
			return nil, err
		}
	}

	return builder.finish(), nil
}

func namespacesForCollection(opts Options) ([]string, error) {
	if len(opts.Namespaces) > 0 && opts.AllNamespaces {
		return nil, errors.New("cannot set namespaces with all-namespaces")
	}
	if len(opts.Namespaces) == 0 {
		if !opts.AllNamespaces {
			return nil, errors.New("namespace or all-namespaces is required")
		}
		return []string{metav1.NamespaceAll}, nil
	}

	seen := map[string]struct{}{}
	namespaces := make([]string, 0, len(opts.Namespaces))
	for _, namespace := range opts.Namespaces {
		if strings.TrimSpace(namespace) == "" {
			return nil, errors.New("namespace entries cannot be empty")
		}
		if _, ok := seen[namespace]; ok {
			continue
		}
		seen[namespace] = struct{}{}
		namespaces = append(namespaces, namespace)
	}
	return namespaces, nil
}

func (c *Collector) collectPods(ctx context.Context, namespace string, builder *inventoryBuilder) error {
	pods, err := c.Client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		ref := model.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}
		builder.addResource(ref, pod.Spec)
	}
	return nil
}

func (c *Collector) collectDeployments(ctx context.Context, namespace string, builder *inventoryBuilder) error {
	deployments, err := c.Client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, deployment := range deployments.Items {
		ref := workloadRef("apps/v1", "Deployment", deployment.Namespace, deployment.Name)
		builder.addResource(ref, deployment.Spec.Template.Spec)
	}
	return nil
}

func (c *Collector) collectStatefulSets(ctx context.Context, namespace string, builder *inventoryBuilder) error {
	statefulSets, err := c.Client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, statefulSet := range statefulSets.Items {
		ref := workloadRef("apps/v1", "StatefulSet", statefulSet.Namespace, statefulSet.Name)
		builder.addResource(ref, statefulSet.Spec.Template.Spec)
	}
	return nil
}

func (c *Collector) collectDaemonSets(ctx context.Context, namespace string, includeZeroDesired bool, builder *inventoryBuilder) error {
	daemonSets, err := c.Client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, daemonSet := range daemonSets.Items {
		if daemonSet.Status.DesiredNumberScheduled == 0 && !includeZeroDesired {
			continue
		}
		ref := workloadRef("apps/v1", "DaemonSet", daemonSet.Namespace, daemonSet.Name)
		builder.addResource(ref, daemonSet.Spec.Template.Spec)
	}
	return nil
}

func (c *Collector) collectJobs(ctx context.Context, namespace string, builder *inventoryBuilder) error {
	jobs, err := c.Client.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, job := range jobs.Items {
		ref := workloadRef("batch/v1", "Job", job.Namespace, job.Name)
		builder.addResource(ref, job.Spec.Template.Spec)
	}
	return nil
}

func (c *Collector) collectCronJobs(ctx context.Context, namespace string, builder *inventoryBuilder) error {
	cronJobs, err := c.Client.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, cronJob := range cronJobs.Items {
		ref := workloadRef("batch/v1", "CronJob", cronJob.Namespace, cronJob.Name)
		builder.addResource(ref, cronJob.Spec.JobTemplate.Spec.Template.Spec)
	}
	return nil
}

func workloadRef(apiVersion, kind, namespace, name string) model.ResourceRef {
	return model.ResourceRef{
		APIVersion: apiVersion,
		Kind:       kind,
		Namespace:  namespace,
		Name:       name,
	}
}

type inventoryBuilder struct {
	inventory *model.Inventory
	images    map[string]*model.ImageInventory
}

func (b *inventoryBuilder) addResource(resource model.ResourceRef, spec corev1.PodSpec) {
	resourceInventory := model.ResourceInventory{Resource: resource}
	for _, c := range spec.Containers {
		b.addContainer(&resourceInventory, resource, c, "container")
	}
	for _, c := range spec.InitContainers {
		b.addContainer(&resourceInventory, resource, c, "initContainer")
	}
	if len(resourceInventory.Images) > 0 {
		b.inventory.Resources = append(b.inventory.Resources, resourceInventory)
	}
}

func (b *inventoryBuilder) addContainer(resourceInventory *model.ResourceInventory, resource model.ResourceRef, c corev1.Container, containerType string) {
	if c.Image == "" {
		return
	}
	restartPolicy := ""
	if c.RestartPolicy != nil {
		restartPolicy = string(*c.RestartPolicy)
	}
	normalized := normalizeImage(c.Image)
	containerImage := model.ContainerImage{
		Name:            c.Name,
		ContainerType:   containerType,
		ImageRef:        c.Image,
		NormalizedImage: normalized,
		RestartPolicy:   restartPolicy,
	}
	resourceInventory.Images = append(resourceInventory.Images, containerImage)

	ref := resource
	ref.ContainerName = c.Name
	ref.ContainerType = containerType
	ref.RestartPolicy = restartPolicy
	image := b.images[c.Image]
	if image == nil {
		image = &model.ImageInventory{
			ImageRef:        c.Image,
			NormalizedImage: normalized,
		}
		b.images[c.Image] = image
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
	left := []string{a.Namespace, a.Kind, a.Name, a.ContainerType, a.ContainerName}
	right := []string{b.Namespace, b.Kind, b.Name, b.ContainerType, b.ContainerName}
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
