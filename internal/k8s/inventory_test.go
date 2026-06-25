package k8s

import (
	"context"
	"testing"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCollectsDeploymentImages(t *testing.T) {
	client := fake.NewSimpleClientset(deployment("default", "web", podSpec(
		container("app", "ghcr.io/acme/web:1.2.3"),
	)))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	img := requireImage(t, inv, "ghcr.io/acme/web:1.2.3")
	if img.NormalizedImage != "ghcr.io/acme/web" {
		t.Fatalf("NormalizedImage = %q, want %q", img.NormalizedImage, "ghcr.io/acme/web")
	}
	requireRef(t, img, model.ResourceRef{
		APIVersion:    "apps/v1",
		Kind:          "Deployment",
		Namespace:     "default",
		Name:          "web",
		ContainerType: "container",
		ContainerName: "app",
	})
}

func TestCollectsStatefulSetImages(t *testing.T) {
	client := fake.NewSimpleClientset(statefulSet("data", "db", podSpec(
		container("postgres", "postgres:16"),
	)))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	img := requireImage(t, inv, "postgres:16")
	requireRef(t, img, model.ResourceRef{
		APIVersion:    "apps/v1",
		Kind:          "StatefulSet",
		Namespace:     "data",
		Name:          "db",
		ContainerType: "container",
		ContainerName: "postgres",
	})
}

func TestCollectsPodRegularAndInitContainers(t *testing.T) {
	client := fake.NewSimpleClientset(pod("default", "standalone", podSpec(
		container("app", "registry.example.com/app:v1"),
		initContainer("migrate", "registry.example.com/migrate:v1", ""),
	)))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireRef(t, requireImage(t, inv, "registry.example.com/app:v1"), model.ResourceRef{
		APIVersion:    "v1",
		Kind:          "Pod",
		Namespace:     "default",
		Name:          "standalone",
		ContainerType: "container",
		ContainerName: "app",
	})
	requireRef(t, requireImage(t, inv, "registry.example.com/migrate:v1"), model.ResourceRef{
		APIVersion:    "v1",
		Kind:          "Pod",
		Namespace:     "default",
		Name:          "standalone",
		ContainerType: "initContainer",
		ContainerName: "migrate",
	})
}

func TestCapturesInitContainerRestartPolicyAlways(t *testing.T) {
	client := fake.NewSimpleClientset(pod("default", "with-sidecar", podSpec(
		container("app", "registry.example.com/app:v1"),
		initContainer("sidecar", "registry.example.com/sidecar:v1", string(corev1.ContainerRestartPolicyAlways)),
	)))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireRef(t, requireImage(t, inv, "registry.example.com/sidecar:v1"), model.ResourceRef{
		APIVersion:    "v1",
		Kind:          "Pod",
		Namespace:     "default",
		Name:          "with-sidecar",
		ContainerType: "initContainer",
		ContainerName: "sidecar",
		RestartPolicy: "Always",
	})
}

func TestExcludesZeroDesiredDaemonSetsByDefault(t *testing.T) {
	client := fake.NewSimpleClientset(daemonSet("kube-system", "agent", 0, podSpec(
		container("agent", "example.com/agent:v1"),
	)))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if imageByRef(inv, "example.com/agent:v1") != nil {
		t.Fatalf("zero-desired daemonset image was collected")
	}
}

func TestIncludesZeroDesiredDaemonSetsWhenEnabled(t *testing.T) {
	client := fake.NewSimpleClientset(daemonSet("kube-system", "agent", 0, podSpec(
		container("agent", "example.com/agent:v1"),
	)))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{
		AllNamespaces:         true,
		IncludeZeroDaemonSets: true,
	})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireRef(t, requireImage(t, inv, "example.com/agent:v1"), model.ResourceRef{
		APIVersion:    "apps/v1",
		Kind:          "DaemonSet",
		Namespace:     "kube-system",
		Name:          "agent",
		ContainerType: "container",
		ContainerName: "agent",
	})
}

func TestCollectsJobAndCronJobImages(t *testing.T) {
	client := fake.NewSimpleClientset(
		job("batch", "once", podSpec(container("runner", "example.com/job:v1"))),
		cronJob("batch", "nightly", podSpec(container("runner", "example.com/cron:v2"))),
	)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireRef(t, requireImage(t, inv, "example.com/job:v1"), model.ResourceRef{
		APIVersion:    "batch/v1",
		Kind:          "Job",
		Namespace:     "batch",
		Name:          "once",
		ContainerType: "container",
		ContainerName: "runner",
	})
	requireRef(t, requireImage(t, inv, "example.com/cron:v2"), model.ResourceRef{
		APIVersion:    "batch/v1",
		Kind:          "CronJob",
		Namespace:     "batch",
		Name:          "nightly",
		ContainerType: "container",
		ContainerName: "runner",
	})
}

func TestNamespaceFilterCollectsOnlyRequestedNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		deployment("default", "web", podSpec(container("app", "example.com/default:v1"))),
		deployment("prod", "web", podSpec(container("app", "example.com/prod:v1"))),
	)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{Namespaces: []string{"prod"}})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if imageByRef(inv, "example.com/default:v1") != nil {
		t.Fatalf("collected image from namespace outside filter")
	}
	requireImage(t, inv, "example.com/prod:v1")
}

func TestRepeatedNamespaceFilterCollectsRequestedNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		deployment("default", "web", podSpec(container("app", "example.com/default:v1"))),
		deployment("prod", "web", podSpec(container("app", "example.com/prod:v1"))),
		deployment("dev", "web", podSpec(container("app", "example.com/dev:v1"))),
	)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{Namespaces: []string{"default", "prod"}})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireImage(t, inv, "example.com/default:v1")
	requireImage(t, inv, "example.com/prod:v1")
	if imageByRef(inv, "example.com/dev:v1") != nil {
		t.Fatalf("collected image from namespace outside repeated filter")
	}
}

func TestRejectsNamespacesWithAllNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset()

	_, err := (&Collector{Client: client}).Collect(context.Background(), Options{
		AllNamespaces: true,
		Namespaces:    []string{"prod"},
	})
	if err == nil {
		t.Fatalf("Collect() error = nil, want conflicting namespace options error")
	}
	if err.Error() != "cannot set namespaces with all-namespaces" {
		t.Fatalf("Collect() error = %q", err.Error())
	}
}

func TestDeduplicatesRepeatedNamespaceInputs(t *testing.T) {
	client := fake.NewSimpleClientset(
		deployment("prod", "web", podSpec(container("app", "example.com/prod:v1"))),
	)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{Namespaces: []string{"prod", "prod"}})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if len(inv.Resources) != 1 {
		t.Fatalf("len(Resources) = %d, want 1: %#v", len(inv.Resources), inv.Resources)
	}
	img := requireImage(t, inv, "example.com/prod:v1")
	if len(img.Resources) != 1 {
		t.Fatalf("len(Image.Resources) = %d, want 1: %#v", len(img.Resources), img.Resources)
	}
}

func TestRejectsEmptyNamespaceEntries(t *testing.T) {
	client := fake.NewSimpleClientset()

	_, err := (&Collector{Client: client}).Collect(context.Background(), Options{Namespaces: []string{"prod", ""}})
	if err == nil {
		t.Fatalf("Collect() error = nil, want empty namespace error")
	}
	if err.Error() != "namespace entries cannot be empty" {
		t.Fatalf("Collect() error = %q", err.Error())
	}
}

func TestRequiresNamespaceOrAllNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset()

	_, err := (&Collector{Client: client}).Collect(context.Background(), Options{})
	if err == nil {
		t.Fatalf("Collect() error = nil, want namespace requirement error")
	}
	if err.Error() != "namespace or all-namespaces is required" {
		t.Fatalf("Collect() error = %q", err.Error())
	}
}

func TestSameImageHasMultipleResourceRefs(t *testing.T) {
	client := fake.NewSimpleClientset(
		deployment("default", "web", podSpec(container("app", "example.com/shared:v1"))),
		pod("default", "debug", podSpec(container("tool", "example.com/shared:v1"))),
	)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	img := requireImage(t, inv, "example.com/shared:v1")
	if len(img.Resources) != 2 {
		t.Fatalf("len(Resources) = %d, want 2: %#v", len(img.Resources), img.Resources)
	}
	requireRef(t, img, model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web", ContainerType: "container", ContainerName: "app"})
	requireRef(t, img, model.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: "default", Name: "debug", ContainerType: "container", ContainerName: "tool"})
}

func TestNormalizedImageStripsTagAndDigestButImageKeyIsFullReference(t *testing.T) {
	tagged := "registry.example.com/team/api:2.0"
	digested := "registry.example.com/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	client := fake.NewSimpleClientset(
		pod("default", "tagged", podSpec(container("api", tagged))),
		pod("default", "digested", podSpec(container("api", digested))),
	)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	taggedImage := requireImage(t, inv, tagged)
	digestedImage := requireImage(t, inv, digested)
	if taggedImage.NormalizedImage != "registry.example.com/team/api" {
		t.Fatalf("tagged NormalizedImage = %q", taggedImage.NormalizedImage)
	}
	if digestedImage.NormalizedImage != "registry.example.com/team/api" {
		t.Fatalf("digested NormalizedImage = %q", digestedImage.NormalizedImage)
	}
	if len(inv.Images) != 2 {
		t.Fatalf("len(Images) = %d, want 2 full image keys", len(inv.Images))
	}
}

func TestNormalizedImageStripsTagWithRegistryPort(t *testing.T) {
	imageRef := "localhost:5000/team/api:1.0"
	client := fake.NewSimpleClientset(pod("default", "api", podSpec(container("api", imageRef))))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	img := requireImage(t, inv, imageRef)
	if img.NormalizedImage != "localhost:5000/team/api" {
		t.Fatalf("NormalizedImage = %q, want %q", img.NormalizedImage, "localhost:5000/team/api")
	}
	if img.ImageRef != imageRef {
		t.Fatalf("ImageRef = %q, want full image ref %q", img.ImageRef, imageRef)
	}
}

func container(name, image string) corev1.Container {
	return corev1.Container{Name: name, Image: image}
}

func initContainer(name, image, restartPolicy string) corev1.Container {
	c := corev1.Container{Name: name, Image: image}
	if restartPolicy != "" {
		policy := corev1.ContainerRestartPolicy(restartPolicy)
		c.RestartPolicy = &policy
	}
	return c
}

func podSpec(containers ...corev1.Container) corev1.PodSpec {
	spec := corev1.PodSpec{}
	for _, c := range containers {
		if c.RestartPolicy != nil {
			spec.InitContainers = append(spec.InitContainers, c)
			continue
		}
		if c.Name == "migrate" || c.Name == "sidecar" {
			spec.InitContainers = append(spec.InitContainers, c)
			continue
		}
		spec.Containers = append(spec.Containers, c)
	}
	return spec
}

func pod(namespace, name string, spec corev1.PodSpec) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}, Spec: spec}
}

func deployment(namespace, name string, spec corev1.PodSpec) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{Spec: spec},
		},
	}
}

func statefulSet(namespace, name string, spec corev1.PodSpec) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{Spec: spec},
		},
	}
}

func daemonSet(namespace, name string, desired int32, spec corev1.PodSpec) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: spec}},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: desired},
	}
}

func job(namespace, name string, spec corev1.PodSpec) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: spec},
		},
	}
}

func cronJob(namespace, name string, spec corev1.PodSpec) *batchv1.CronJob {
	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: batchv1.CronJobSpec{
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: spec}},
			},
		},
	}
}

func requireImage(t *testing.T, inv *model.Inventory, imageRef string) model.ImageInventory {
	t.Helper()
	img := imageByRef(inv, imageRef)
	if img == nil {
		t.Fatalf("missing image %q in %#v", imageRef, inv.Images)
	}
	return *img
}

func imageByRef(inv *model.Inventory, imageRef string) *model.ImageInventory {
	for i := range inv.Images {
		if inv.Images[i].ImageRef == imageRef {
			return &inv.Images[i]
		}
	}
	return nil
}

func requireRef(t *testing.T, img model.ImageInventory, want model.ResourceRef) {
	t.Helper()
	for _, got := range img.Resources {
		if got.APIVersion == want.APIVersion &&
			got.Kind == want.Kind &&
			got.Namespace == want.Namespace &&
			got.Name == want.Name &&
			got.ContainerType == want.ContainerType &&
			got.ContainerName == want.ContainerName &&
			got.RestartPolicy == want.RestartPolicy {
			return
		}
	}
	t.Fatalf("missing ref %#v in %#v", want, img.Resources)
}
