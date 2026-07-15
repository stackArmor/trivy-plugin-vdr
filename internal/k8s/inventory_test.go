package k8s

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
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

func TestCollectsWorkloadTemplateLabels(t *testing.T) {
	deploy := deployment("default", "web", podSpec(container("app", "ghcr.io/acme/web:1.2.3")))
	deploy.Spec.Template.Labels = map[string]string{"app": "web", "tier": "frontend"}
	client := fake.NewSimpleClientset(deploy)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireResourceLabels(t, inv, "web", map[string]string{"app": "web", "tier": "frontend"})
}

func TestMergesWorkloadAndTemplateLabels(t *testing.T) {
	deploy := deployment("default", "web", podSpec(container("app", "ghcr.io/acme/web:1.2.3")))
	// Workload-object labels (e.g. from Helm values.labels) plus pod-template labels;
	// the pod template wins on a key conflict, the rest are unioned.
	deploy.Labels = map[string]string{"vdr.fedramp.io/asset-archetype": "app-tier", "tier": "workload"}
	deploy.Spec.Template.Labels = map[string]string{"app": "web", "tier": "template"}
	client := fake.NewSimpleClientset(deploy)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	requireResourceLabels(t, inv, "web", map[string]string{
		"vdr.fedramp.io/asset-archetype": "app-tier",
		"app":                            "web",
		"tier":                           "template", // template wins over workload
	})
}

func TestCollectsNamespaceMetadata(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "prod",
		Labels: map[string]string{"vdr.fedramp.io/class": "C", "vdr.fedramp.io/multi-agency": "true"},
	}}
	deploy := deployment("prod", "web", podSpec(container("app", "ghcr.io/acme/web:1.2.3")))
	client := fake.NewSimpleClientset(ns, deploy)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	got := inv.Namespaces["prod"]
	want := map[string]string{"vdr.fedramp.io/class": "C", "vdr.fedramp.io/multi-agency": "true"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Namespaces[prod] = %#v, want %#v", got, want)
	}
}

func TestCollectsClusterDefaultsConfigMap(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "fedramp-vdr-trivy", Name: "vdr-fedramp"},
		Data:       map[string]string{"class": "C", "multiAgency": "false"},
	}
	deploy := deployment("default", "web", podSpec(container("app", "ghcr.io/acme/web:1.2.3")))
	client := fake.NewSimpleClientset(cm, deploy)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if inv.ClusterDefaults["class"] != "C" || inv.ClusterDefaults["multiAgency"] != "false" {
		t.Fatalf("ClusterDefaults = %#v, want class=C multiAgency=false", inv.ClusterDefaults)
	}
	for _, w := range inv.Warnings {
		if strings.Contains(w, "vdr-fedramp") {
			t.Errorf("unexpected ConfigMap warning when present: %q", w)
		}
	}
}

func TestCollectsClusterDefaultsFromCustomConfigMapNamespace(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "custom-vdr", Name: "vdr-fedramp"},
		Data:       map[string]string{"class": "D", "multiAgency": "true"},
	}
	deploy := deployment("default", "web", podSpec(container("app", "ghcr.io/acme/web:1.2.3")))
	client := fake.NewSimpleClientset(cm, deploy)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{
		AllNamespaces:             true,
		ClusterConfigMapNamespace: "custom-vdr",
	})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if inv.ClusterDefaults["class"] != "D" || inv.ClusterDefaults["multiAgency"] != "true" {
		t.Fatalf("ClusterDefaults = %#v, want class=D multiAgency=true", inv.ClusterDefaults)
	}
	for _, w := range inv.Warnings {
		if strings.Contains(w, "built-in defaults") {
			t.Errorf("unexpected built-in defaults warning when custom ConfigMap present: %q", w)
		}
	}
}

func TestWarnsWhenClusterConfigMapMissing(t *testing.T) {
	deploy := deployment("default", "web", podSpec(container("app", "ghcr.io/acme/web:1.2.3")))
	client := fake.NewSimpleClientset(deploy) // no vdr-fedramp ConfigMap

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if inv.ClusterDefaults != nil {
		t.Errorf("ClusterDefaults = %#v, want nil when ConfigMap absent", inv.ClusterDefaults)
	}
	found := false
	for _, w := range inv.Warnings {
		if strings.Contains(w, "fedramp-vdr-trivy/vdr-fedramp") && strings.Contains(w, "built-in defaults") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning about the missing ConfigMap, got %#v", inv.Warnings)
	}
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

func TestCapturesPrivilegedCapabilitiesAndReadOnlyRootFilesystem(t *testing.T) {
	privileged := true
	readOnlyRootFilesystem := true
	client := fake.NewSimpleClientset(pod("default", "hardened", podSpec(corev1.Container{
		Name:  "app",
		Image: "registry.example.com/app:v1",
		SecurityContext: &corev1.SecurityContext{
			Privileged:             &privileged,
			ReadOnlyRootFilesystem: &readOnlyRootFilesystem,
			Capabilities: &corev1.Capabilities{
				Add:  []corev1.Capability{"NET_ADMIN", "SYS_TIME"},
				Drop: []corev1.Capability{"ALL"},
			},
		},
	})))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireContainerSecurity(t, inv, "hardened", "app", model.ContainerSecurity{
		Privileged:             boolPtr(true),
		CapabilitiesAdd:        []string{"NET_ADMIN", "SYS_TIME"},
		CapabilitiesDrop:       []string{"ALL"},
		ReadOnlyRootFilesystem: boolPtr(true),
	})
}

func TestCapturesContainerSeccompProfile(t *testing.T) {
	profile := "profiles/audit.json"
	client := fake.NewSimpleClientset(pod("default", "seccomp", podSpec(corev1.Container{
		Name:  "app",
		Image: "registry.example.com/app:v1",
		SecurityContext: &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{
				Type:             corev1.SeccompProfileTypeLocalhost,
				LocalhostProfile: &profile,
			},
		},
	})))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireContainerSecurity(t, inv, "seccomp", "app", model.ContainerSecurity{
		SeccompProfile: &model.SecurityProfile{Type: "Localhost", LocalhostProfile: "profiles/audit.json"},
	})
}

func TestCapturesPodSeccompProfileFallback(t *testing.T) {
	spec := podSpec(container("app", "registry.example.com/app:v1"))
	spec.SecurityContext = &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	client := fake.NewSimpleClientset(pod("default", "pod-seccomp", spec))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireContainerSecurity(t, inv, "pod-seccomp", "app", model.ContainerSecurity{
		SeccompProfile: &model.SecurityProfile{Type: "RuntimeDefault"},
	})
}

func TestCapturesAppArmorAnnotationForContainer(t *testing.T) {
	client := fake.NewSimpleClientset(podWithAnnotations("default", "apparmor", map[string]string{
		"container.apparmor.security.beta.kubernetes.io/app": "localhost/k8s-apparmor-example-deny-write",
	}, podSpec(container("app", "registry.example.com/app:v1"))))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireContainerSecurity(t, inv, "apparmor", "app", model.ContainerSecurity{
		AppArmorProfile: &model.SecurityProfile{Type: "Localhost", LocalhostProfile: "k8s-apparmor-example-deny-write"},
	})
}

func TestCapturesContainerAppArmorProfile(t *testing.T) {
	profile := "profiles/container-apparmor"
	client := fake.NewSimpleClientset(pod("default", "container-apparmor", podSpec(corev1.Container{
		Name:  "app",
		Image: "registry.example.com/app:v1",
		SecurityContext: &corev1.SecurityContext{
			AppArmorProfile: &corev1.AppArmorProfile{
				Type:             corev1.AppArmorProfileTypeLocalhost,
				LocalhostProfile: &profile,
			},
		},
	})))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireContainerSecurity(t, inv, "container-apparmor", "app", model.ContainerSecurity{
		AppArmorProfile: &model.SecurityProfile{Type: "Localhost", LocalhostProfile: "profiles/container-apparmor"},
	})
}

func TestCapturesPodAppArmorProfileFallback(t *testing.T) {
	spec := podSpec(container("app", "registry.example.com/app:v1"))
	spec.SecurityContext = &corev1.PodSecurityContext{
		AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault},
	}
	client := fake.NewSimpleClientset(pod("default", "pod-apparmor", spec))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireContainerSecurity(t, inv, "pod-apparmor", "app", model.ContainerSecurity{
		AppArmorProfile: &model.SecurityProfile{Type: "RuntimeDefault"},
	})
}

func TestAppArmorAnnotationOverridesPodProfile(t *testing.T) {
	spec := podSpec(container("app", "registry.example.com/app:v1"))
	spec.SecurityContext = &corev1.PodSecurityContext{
		AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault},
	}
	client := fake.NewSimpleClientset(podWithAnnotations("default", "apparmor-precedence", map[string]string{
		"container.apparmor.security.beta.kubernetes.io/app": "localhost/container-specific",
	}, spec))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireContainerSecurity(t, inv, "apparmor-precedence", "app", model.ContainerSecurity{
		AppArmorProfile: &model.SecurityProfile{Type: "Localhost", LocalhostProfile: "container-specific"},
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

func TestCollectExposureObjectsCollectsTypedAndUnstructuredResources(t *testing.T) {
	ingressClassName := "gce"
	client := fake.NewSimpleClientset(
		serviceForExposure("default", "web-svc"),
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web-ing"},
			Spec:       networkingv1.IngressSpec{IngressClassName: &ingressClassName},
		},
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "gce"}},
	)
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		exposureListKinds(),
	)
	if _, err := dynamicClient.Resource(schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}).Namespace("default").Create(
		context.Background(),
		unstructuredExposureObject("gateway.networking.k8s.io/v1", "Gateway", "default", "public-gw"),
		metav1.CreateOptions{},
	); err != nil {
		t.Fatalf("create gateway fixture: %v", err)
	}
	if _, err := dynamicClient.Resource(schema.GroupVersionResource{Group: "cloud.google.com", Version: "v1", Resource: "backendconfigs"}).Namespace("default").Create(
		context.Background(),
		unstructuredExposureObject("cloud.google.com/v1", "BackendConfig", "default", "web-backend"),
		metav1.CreateOptions{},
	); err != nil {
		t.Fatalf("create backendconfig fixture: %v", err)
	}

	objects, err := (&Collector{Client: client, Dynamic: dynamicClient}).CollectExposureObjects(context.Background(), Options{Namespaces: []string{"default"}})
	if err != nil {
		t.Fatalf("CollectExposureObjects() error = %v", err)
	}

	if len(objects.Services) != 1 || objects.Services[0].Name != "web-svc" {
		t.Fatalf("Services = %#v, want web-svc", objects.Services)
	}
	if len(objects.Ingresses) != 1 || objects.Ingresses[0].Name != "web-ing" {
		t.Fatalf("Ingresses = %#v, want web-ing", objects.Ingresses)
	}
	if len(objects.IngressClasses) != 1 || objects.IngressClasses[0].Name != "gce" {
		t.Fatalf("IngressClasses = %#v, want gce", objects.IngressClasses)
	}
	if len(objects.Unstructured) != 2 {
		t.Fatalf("Unstructured len = %d, want 2: %#v", len(objects.Unstructured), objects.Unstructured)
	}
}

func TestCollectExposureObjectsWarnsAndContinuesOnOptionalDynamicErrors(t *testing.T) {
	client := fake.NewSimpleClientset(serviceForExposure("default", "web-svc"))
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), exposureListKinds())
	dynamicClient.PrependReactor("list", "gateways", func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"},
			"",
			nil,
		)
	})

	objects, warnings, err := (&Collector{Client: client, Dynamic: dynamicClient}).CollectExposureObjectsWithWarnings(context.Background(), Options{Namespaces: []string{"default"}})
	if err != nil {
		t.Fatalf("CollectExposureObjectsWithWarnings() error = %v, want nil for optional dynamic error", err)
	}

	if len(objects.Services) != 1 || objects.Services[0].Name != "web-svc" {
		t.Fatalf("Services = %#v, want typed resources retained", objects.Services)
	}
	if len(warnings) == 0 {
		t.Fatal("warnings len = 0, want optional resource warning")
	}
	if !strings.Contains(warnings[0], "gateway.networking.k8s.io") || !strings.Contains(warnings[0], "forbidden") {
		t.Fatalf("warning = %q, want forbidden Gateway context", warnings[0])
	}
}

func TestCollectExposureObjectsWarnsAndContinuesOnTypedRBACErrors(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "services", func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "", nil)
	})

	_, warnings, err := (&Collector{Client: client}).CollectExposureObjectsWithWarnings(context.Background(), Options{Namespaces: []string{"default"}})
	if err != nil {
		t.Fatalf("CollectExposureObjectsWithWarnings() error = %v, want nil for typed exposure RBAC error", err)
	}
	if len(warnings) == 0 {
		t.Fatal("warnings len = 0, want typed exposure warning")
	}
	if !strings.Contains(warnings[0], "Services") || !strings.Contains(warnings[0], "forbidden") {
		t.Fatalf("warning = %q, want forbidden Services context", warnings[0])
	}
}

func TestCollectExcludesControllerOwnedPods(t *testing.T) {
	client := fake.NewSimpleClientset(
		pod("default", "standalone", podSpec(container("app", "example.com/standalone:v1"))),
		controlledPod("default", "rs-pod", "ReplicaSet", podSpec(container("app", "example.com/deploy:v1"))),
		controlledPod("default", "sts-pod", "StatefulSet", podSpec(container("app", "example.com/sts:v1"))),
		controlledPod("default", "job-pod", "Job", podSpec(container("app", "example.com/job:v1"))),
		controlledPod("default", "operator-pod", "FooKind", podSpec(container("app", "example.com/operator:v1"))),
	)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	got := map[string]bool{}
	for _, image := range inv.Images {
		got[image.ImageRef] = true
	}
	// Standalone and operator/CRD-owned pods are kept.
	for _, want := range []string{"example.com/standalone:v1", "example.com/operator:v1"} {
		if !got[want] {
			t.Fatalf("expected image %q in inventory, got %v", want, got)
		}
	}
	// Pods owned by collected controllers are skipped (the controller template
	// would supply these images instead).
	for _, skip := range []string{"example.com/deploy:v1", "example.com/sts:v1", "example.com/job:v1"} {
		if got[skip] {
			t.Fatalf("did not expect controller-owned pod image %q in inventory", skip)
		}
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

func controlledPod(namespace, name, ownerKind string, spec corev1.PodSpec) *corev1.Pod {
	controller := true
	p := pod(namespace, name, spec)
	p.OwnerReferences = []metav1.OwnerReference{{Kind: ownerKind, Name: "owner", Controller: &controller}}
	return p
}

func podWithAnnotations(namespace, name string, annotations map[string]string, spec corev1.PodSpec) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Annotations: annotations}, Spec: spec}
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

func requireContainerSecurity(t *testing.T, inv *model.Inventory, resourceName, containerName string, want model.ContainerSecurity) {
	t.Helper()
	for _, resource := range inv.Resources {
		if resource.Resource.Name != resourceName {
			continue
		}
		for _, image := range resource.Images {
			if image.Name == containerName {
				if image.Security == nil {
					t.Fatalf("Security = nil for container %q", containerName)
				}
				requireSecurity(t, *image.Security, want)
				return
			}
		}
	}
	t.Fatalf("missing container %q on resource %q", containerName, resourceName)
}

func requireResourceLabels(t *testing.T, inv *model.Inventory, resourceName string, want map[string]string) {
	t.Helper()
	for _, resource := range inv.Resources {
		if resource.Resource.Name == resourceName {
			if !reflect.DeepEqual(resource.Labels, want) {
				t.Fatalf("Labels = %#v, want %#v", resource.Labels, want)
			}
			return
		}
	}
	t.Fatalf("missing resource %q", resourceName)
}

func requireSecurity(t *testing.T, got, want model.ContainerSecurity) {
	t.Helper()
	if got.Privileged == nil != (want.Privileged == nil) {
		t.Fatalf("Privileged = %v, want %v", got.Privileged, want.Privileged)
	}
	if got.Privileged != nil && *got.Privileged != *want.Privileged {
		t.Fatalf("Privileged = %v, want %v", *got.Privileged, *want.Privileged)
	}
	if got.ReadOnlyRootFilesystem == nil != (want.ReadOnlyRootFilesystem == nil) {
		t.Fatalf("ReadOnlyRootFilesystem = %v, want %v", got.ReadOnlyRootFilesystem, want.ReadOnlyRootFilesystem)
	}
	if got.ReadOnlyRootFilesystem != nil && *got.ReadOnlyRootFilesystem != *want.ReadOnlyRootFilesystem {
		t.Fatalf("ReadOnlyRootFilesystem = %v, want %v", *got.ReadOnlyRootFilesystem, *want.ReadOnlyRootFilesystem)
	}
	if !stringSlicesEqual(got.CapabilitiesAdd, want.CapabilitiesAdd) {
		t.Fatalf("CapabilitiesAdd = %#v, want %#v", got.CapabilitiesAdd, want.CapabilitiesAdd)
	}
	if !stringSlicesEqual(got.CapabilitiesDrop, want.CapabilitiesDrop) {
		t.Fatalf("CapabilitiesDrop = %#v, want %#v", got.CapabilitiesDrop, want.CapabilitiesDrop)
	}
	if !profilesEqual(got.SeccompProfile, want.SeccompProfile) {
		t.Fatalf("SeccompProfile = %#v, want %#v", got.SeccompProfile, want.SeccompProfile)
	}
	if !profilesEqual(got.AppArmorProfile, want.AppArmorProfile) {
		t.Fatalf("AppArmorProfile = %#v, want %#v", got.AppArmorProfile, want.AppArmorProfile)
	}
}

func profilesEqual(got, want *model.SecurityProfile) bool {
	if got == nil || want == nil {
		return got == want
	}
	return got.Type == want.Type && got.LocalhostProfile == want.LocalhostProfile
}

func stringSlicesEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func boolPtr(v bool) *bool {
	return &v
}

func serviceForExposure(namespace, name string) *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
}

func unstructuredExposureObject(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
	}}
}

func exposureListKinds() map[schema.GroupVersionResource]string {
	listKinds := map[schema.GroupVersionResource]string{}
	for _, resource := range exposureResources {
		listKinds[resource.gvr] = resourceListKind(resource.gvr.Resource)
	}
	return listKinds
}

func resourceListKind(resource string) string {
	switch resource {
	case "gateways":
		return "GatewayList"
	case "httproutes":
		return "HTTPRouteList"
	case "grpcroutes":
		return "GRPCRouteList"
	case "tcproutes":
		return "TCPRouteList"
	case "tlsroutes":
		return "TLSRouteList"
	case "referencegrants":
		return "ReferenceGrantList"
	case "gcpbackendpolicies":
		return "GCPBackendPolicyList"
	case "backendconfigs":
		return "BackendConfigList"
	case "ingressclassparams":
		return "IngressClassParamsList"
	case "loadbalancerconfigurations":
		return "LoadBalancerConfigurationList"
	default:
		return "UnstructuredList"
	}
}

func TestCollectSkipsCronJobOwnedJobs(t *testing.T) {
	controller := true
	owned := job("batch", "nightly-29123456", podSpec(container("runner", "example.com/cron:v2")))
	owned.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "nightly", Controller: &controller}}
	client := fake.NewSimpleClientset(
		owned,
		job("batch", "helm-hook", podSpec(container("runner", "example.com/hook:v1"))),
		cronJob("batch", "nightly", podSpec(container("runner", "example.com/cron:v2"))),
	)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	requireRef(t, requireImage(t, inv, "example.com/hook:v1"), model.ResourceRef{
		APIVersion:    "batch/v1",
		Kind:          "Job",
		Namespace:     "batch",
		Name:          "helm-hook",
		ContainerType: "container",
		ContainerName: "runner",
	})
	for _, ref := range requireImage(t, inv, "example.com/cron:v2").Resources {
		if ref.Kind == "Job" {
			t.Fatalf("CronJob-owned Job was inventoried: %#v", ref)
		}
	}
}
