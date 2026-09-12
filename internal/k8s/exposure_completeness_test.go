package k8s

import (
	"context"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"testing"
)

func TestExposureCollectionCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		opts                                       Options
		missingDynamic, forbidden, absentCRD, want bool
	}{
		{name: "complete", opts: Options{AllNamespaces: true}, want: true},
		{name: "namespace limited", opts: Options{Namespaces: []string{"default"}}},
		{name: "excluded namespace", opts: Options{AllNamespaces: true, ExcludeNamespaces: []string{"private"}}},
		{name: "no dynamic discovery", opts: Options{AllNamespaces: true}, missingDynamic: true},
		{name: "forbidden", opts: Options{AllNamespaces: true}, forbidden: true},
		{name: "absent optional CRD", opts: Options{AllNamespaces: true}, absentCRD: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			dynamic := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), exposureListKinds())
			if tc.forbidden || tc.absentCRD {
				dynamic.PrependReactor("list", "gateways", func(clienttesting.Action) (bool, runtime.Object, error) {
					resource := schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"}
					if tc.absentCRD {
						return true, nil, apierrors.NewNotFound(resource, "")
					}
					return true, nil, apierrors.NewForbidden(resource, "", nil)
				})
			}
			collector := &Collector{Client: client, Dynamic: dynamic}
			if tc.missingDynamic {
				collector.Dynamic = nil
			}
			objects, _, err := collector.CollectExposureObjectsWithWarnings(context.Background(), tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if objects.CollectionComplete != tc.want {
				t.Fatalf("complete=%v, want %v", objects.CollectionComplete, tc.want)
			}
		})
	}
}

func TestInventoryCapturesDirectNodeAccess(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hostNetwork bool
		hostPort    int32
		want        bool
	}{
		{"ordinary", false, 0, false}, {"host network", true, 0, true}, {"host port", false, 8080, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := inventoryBuilder{inventory: &model.Inventory{}, images: map[string]*model.ImageInventory{}}
			builder.addResource(model.ResourceRef{Kind: "Deployment", Namespace: "default", Name: "app"}, corev1.PodSpec{
				HostNetwork: tc.hostNetwork,
				Containers:  []corev1.Container{{Name: "app", Image: "app:v1", Ports: []corev1.ContainerPort{{HostPort: tc.hostPort}}}},
			}, nil, nil, nil, nil)
			if builder.inventory.Resources[0].DirectNodeAccess != tc.want {
				t.Fatal("direct node access was not captured")
			}
		})
	}
}
