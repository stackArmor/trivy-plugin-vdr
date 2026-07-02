package k8s

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Options struct {
	Namespaces            []string
	AllNamespaces         bool
	IncludeZeroDaemonSets bool
	// ClusterConfigMapNamespace/Name locate the cluster-wide FedRAMP metadata
	// ConfigMap (cluster default class / multi-agency). Defaults:
	// fedramp-vdr-trivy/vdr-fedramp.
	ClusterConfigMapNamespace string
	ClusterConfigMapName      string
	// CollectWorkloadFacts enables control-credit verification-fact collection
	// (pod-spec signals plus NetworkPolicies and PodDisruptionBudgets). Off by
	// default; main turns it on only when a taxonomy is loaded, so a run with no
	// --taxonomy makes no extra API calls and produces identical output.
	CollectWorkloadFacts bool
}

const (
	defaultClusterConfigMapNamespace = "fedramp-vdr-trivy"
	defaultClusterConfigMapName      = "vdr-fedramp"
)

type Collector struct {
	Client      kubernetes.Interface
	Dynamic     dynamic.Interface
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
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, "", err
	}

	contextName := rawConfig.CurrentContext
	return &Collector{Client: client, Dynamic: dynamicClient, ContextName: contextName}, contextName, nil
}

func (c *Collector) Collect(ctx context.Context, opts Options) (*model.Inventory, error) {
	if c == nil || c.Client == nil {
		return nil, errors.New("kubernetes collector requires a client")
	}

	builder := inventoryBuilder{
		inventory:    &model.Inventory{ContextName: c.ContextName},
		images:       map[string]*model.ImageInventory{},
		collectFacts: opts.CollectWorkloadFacts,
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

	// Namespace-level FedRAMP metadata and cluster-wide defaults are best-effort:
	// they enrich scoring but must not fail the scan if RBAC or the ConfigMap is
	// absent.
	c.collectNamespaceMetadata(ctx, opts, &builder)
	c.collectClusterDefaults(ctx, opts, &builder)

	// Control-credit verification facts drawn from cluster-scoped objects
	// (NetworkPolicies, PodDisruptionBudgets). Best-effort like the metadata above.
	if opts.CollectWorkloadFacts {
		for _, namespace := range namespaces {
			c.collectNetworkPolicyFacts(ctx, namespace, &builder)
			c.collectPodDisruptionBudgetFacts(ctx, namespace, &builder)
		}
	}

	return builder.finish(), nil
}

// collectNamespaceMetadata records each in-scope namespace's object labels so
// scoring can resolve namespace-level archetype/multi-agency/class metadata.
func (c *Collector) collectNamespaceMetadata(ctx context.Context, opts Options, builder *inventoryBuilder) {
	labels := map[string]map[string]string{}
	if opts.AllNamespaces || len(opts.Namespaces) == 0 {
		list, err := c.Client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return
		}
		for _, ns := range list.Items {
			if len(ns.Labels) > 0 {
				labels[ns.Name] = ns.Labels
			}
		}
	} else {
		for _, name := range opts.Namespaces {
			ns, err := c.Client.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			if len(ns.Labels) > 0 {
				labels[ns.Name] = ns.Labels
			}
		}
	}
	if len(labels) > 0 {
		builder.inventory.Namespaces = labels
	}
}

// collectClusterDefaults reads the cluster-wide FedRAMP metadata ConfigMap
// (e.g. class, multiAgency). Best-effort: a missing ConfigMap is not an error.
func (c *Collector) collectClusterDefaults(ctx context.Context, opts Options, builder *inventoryBuilder) {
	nsName := opts.ClusterConfigMapNamespace
	if nsName == "" {
		nsName = defaultClusterConfigMapNamespace
	}
	cmName := opts.ClusterConfigMapName
	if cmName == "" {
		cmName = defaultClusterConfigMapName
	}
	cm, err := c.Client.CoreV1().ConfigMaps(nsName).Get(ctx, cmName, metav1.GetOptions{})
	if err != nil {
		builder.inventory.Warnings = append(builder.inventory.Warnings, fmt.Sprintf(
			"cluster FedRAMP ConfigMap %s/%s not read (%v); PAIN scoring uses built-in defaults (Class B, single-agency) and has no tenant archetype rules",
			nsName, cmName, err))
		return
	}
	if len(cm.Data) == 0 {
		builder.inventory.Warnings = append(builder.inventory.Warnings, fmt.Sprintf(
			"cluster FedRAMP ConfigMap %s/%s has no data; PAIN scoring uses built-in defaults (Class B, single-agency)",
			nsName, cmName))
		return
	}
	builder.inventory.ClusterDefaults = cm.Data
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

// collectedControllerKinds are the controller kinds whose pod templates this
// collector already inventories. Pods owned by one of these are redundant and
// are skipped so each workload is counted once. A Deployment owns its pods via a
// ReplicaSet, and a CronJob via a Job.
var collectedControllerKinds = map[string]bool{
	"ReplicaSet":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"Job":         true,
}

func (c *Collector) collectPods(ctx context.Context, namespace string, builder *inventoryBuilder) error {
	pods, err := c.Client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		// Only inventory standalone pods. Pods managed by a controller we already
		// collect (Deployment/ReplicaSet, StatefulSet, DaemonSet, Job/CronJob) are
		// covered by that controller's template; pods owned by other controllers
		// (e.g. operators/CRDs) are kept so their images are not missed.
		if ownedByCollectedController(pod) {
			continue
		}
		ref := model.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}
		builder.addResource(ref, pod.Spec, pod.Annotations, pod.Labels, pod.Labels)
	}
	return nil
}

func ownedByCollectedController(pod corev1.Pod) bool {
	for _, owner := range pod.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && collectedControllerKinds[owner.Kind] {
			return true
		}
	}
	return false
}

func (c *Collector) collectDeployments(ctx context.Context, namespace string, builder *inventoryBuilder) error {
	deployments, err := c.Client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, deployment := range deployments.Items {
		ref := workloadRef("apps/v1", "Deployment", deployment.Namespace, deployment.Name)
		builder.addResourceWithReplicas(ref, deployment.Spec.Template.Spec, deployment.Spec.Template.Annotations, deployment.Labels, deployment.Spec.Template.Labels, deployment.Spec.Replicas)
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
		builder.addResourceWithReplicas(ref, statefulSet.Spec.Template.Spec, statefulSet.Spec.Template.Annotations, statefulSet.Labels, statefulSet.Spec.Template.Labels, statefulSet.Spec.Replicas)
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
		builder.addResource(ref, daemonSet.Spec.Template.Spec, daemonSet.Spec.Template.Annotations, daemonSet.Labels, daemonSet.Spec.Template.Labels)
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
		builder.addResource(ref, job.Spec.Template.Spec, job.Spec.Template.Annotations, job.Labels, job.Spec.Template.Labels)
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
		builder.addResource(ref, cronJob.Spec.JobTemplate.Spec.Template.Spec, cronJob.Spec.JobTemplate.Spec.Template.Annotations, cronJob.Labels, cronJob.Spec.JobTemplate.Spec.Template.Labels)
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
	inventory    *model.Inventory
	images       map[string]*model.ImageInventory
	collectFacts bool
}

// addResource records a workload. workloadLabels are the labels on the workload
// object itself (e.g. Deployment.metadata.labels) and templateLabels are the pod
// template labels. They are merged into ResourceInventory.Labels with the pod
// template winning on conflict, so VDR archetype tags applied at either level
// (Helm values.labels render to the workload object) are visible to scoring.
func (b *inventoryBuilder) addResource(resource model.ResourceRef, spec corev1.PodSpec, annotations, workloadLabels, templateLabels map[string]string) {
	b.addResourceWithReplicas(resource, spec, annotations, workloadLabels, templateLabels, nil)
}

func (b *inventoryBuilder) addResourceWithReplicas(resource model.ResourceRef, spec corev1.PodSpec, annotations, workloadLabels, templateLabels map[string]string, replicas *int32) {
	resourceInventory := model.ResourceInventory{Resource: resource, Labels: mergeLabels(workloadLabels, templateLabels)}
	for _, c := range spec.Containers {
		b.addContainer(&resourceInventory, resource, spec, annotations, c, "container")
	}
	for _, c := range spec.InitContainers {
		b.addContainer(&resourceInventory, resource, spec, annotations, c, "initContainer")
	}
	if len(resourceInventory.Images) > 0 {
		if b.collectFacts {
			resourceInventory.Facts = podSpecFacts(spec, annotations, replicas)
		}
		b.inventory.Resources = append(b.inventory.Resources, resourceInventory)
	}
}

func (b *inventoryBuilder) addContainer(resourceInventory *model.ResourceInventory, resource model.ResourceRef, spec corev1.PodSpec, annotations map[string]string, c corev1.Container, containerType string) {
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
		Security:        containerSecurity(spec, annotations, c),
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

// mergeLabels combines workload-object labels with pod-template labels. The pod
// template wins on key conflict. Returns nil when both are empty.
func mergeLabels(workload, template map[string]string) map[string]string {
	if len(workload) == 0 && len(template) == 0 {
		return nil
	}
	merged := make(map[string]string, len(workload)+len(template))
	for k, v := range workload {
		merged[k] = v
	}
	for k, v := range template {
		merged[k] = v
	}
	return merged
}

func containerSecurity(spec corev1.PodSpec, annotations map[string]string, c corev1.Container) *model.ContainerSecurity {
	security := model.ContainerSecurity{}
	if c.SecurityContext != nil {
		security.Privileged = copyBool(c.SecurityContext.Privileged)
		security.ReadOnlyRootFilesystem = copyBool(c.SecurityContext.ReadOnlyRootFilesystem)
		if c.SecurityContext.Capabilities != nil {
			security.CapabilitiesAdd = capabilitiesToStrings(c.SecurityContext.Capabilities.Add)
			security.CapabilitiesDrop = capabilitiesToStrings(c.SecurityContext.Capabilities.Drop)
		}
		security.SeccompProfile = seccompProfile(c.SecurityContext.SeccompProfile)
		security.AppArmorProfile = appArmorProfile(c.SecurityContext.AppArmorProfile)
	}
	if security.SeccompProfile == nil && spec.SecurityContext != nil {
		security.SeccompProfile = seccompProfile(spec.SecurityContext.SeccompProfile)
	}
	if security.AppArmorProfile == nil {
		security.AppArmorProfile = appArmorAnnotationProfile(annotations, c.Name)
	}
	if security.AppArmorProfile == nil && spec.SecurityContext != nil {
		security.AppArmorProfile = appArmorProfile(spec.SecurityContext.AppArmorProfile)
	}
	if isZeroContainerSecurity(security) {
		return nil
	}
	return &security
}

func copyBool(v *bool) *bool {
	if v == nil {
		return nil
	}
	copied := *v
	return &copied
}

func capabilitiesToStrings(capabilities []corev1.Capability) []string {
	if len(capabilities) == 0 {
		return nil
	}
	values := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		values = append(values, string(capability))
	}
	return values
}

func seccompProfile(profile *corev1.SeccompProfile) *model.SecurityProfile {
	if profile == nil {
		return nil
	}
	securityProfile := &model.SecurityProfile{Type: string(profile.Type)}
	if profile.LocalhostProfile != nil {
		securityProfile.LocalhostProfile = *profile.LocalhostProfile
	}
	return securityProfile
}

func appArmorProfile(profile *corev1.AppArmorProfile) *model.SecurityProfile {
	if profile == nil {
		return nil
	}
	securityProfile := &model.SecurityProfile{Type: string(profile.Type)}
	if profile.LocalhostProfile != nil {
		securityProfile.LocalhostProfile = *profile.LocalhostProfile
	}
	return securityProfile
}

func appArmorAnnotationProfile(annotations map[string]string, containerName string) *model.SecurityProfile {
	value := annotations["container.apparmor.security.beta.kubernetes.io/"+containerName]
	if value == "" {
		return nil
	}
	switch {
	case value == "runtime/default":
		return &model.SecurityProfile{Type: string(corev1.AppArmorProfileTypeRuntimeDefault)}
	case value == "unconfined":
		return &model.SecurityProfile{Type: string(corev1.AppArmorProfileTypeUnconfined)}
	case strings.HasPrefix(value, "localhost/"):
		return &model.SecurityProfile{
			Type:             string(corev1.AppArmorProfileTypeLocalhost),
			LocalhostProfile: strings.TrimPrefix(value, "localhost/"),
		}
	default:
		return &model.SecurityProfile{Type: value}
	}
}

func isZeroContainerSecurity(security model.ContainerSecurity) bool {
	return security.Privileged == nil &&
		len(security.CapabilitiesAdd) == 0 &&
		len(security.CapabilitiesDrop) == 0 &&
		security.ReadOnlyRootFilesystem == nil &&
		security.SeccompProfile == nil &&
		security.AppArmorProfile == nil
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
