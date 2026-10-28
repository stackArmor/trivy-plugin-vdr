package k8s

import (
	"context"
	"fmt"

	"github.com/stackArmor/trivy-plugin-vdr/internal/exposure"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type exposureResource struct {
	gvr        schema.GroupVersionResource
	namespaced bool
	// fallbackVersions are tried in order when gvr.Version is not served.
	// Gateway API v1.6 serves TCPRoute, TLSRoute, and UDPRoute only at v1 in
	// the Standard channel; older and Experimental installs still serve the
	// alpha versions.
	fallbackVersions []string
}

var exposureResources = []exposureResource{
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "tcproutes"}, namespaced: true, fallbackVersions: []string{"v1alpha2"}},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "tlsroutes"}, namespaced: true, fallbackVersions: []string{"v1alpha3", "v1alpha2"}},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "udproutes"}, namespaced: true, fallbackVersions: []string{"v1alpha2"}},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "referencegrants"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "networking.gke.io", Version: "v1", Resource: "gcpbackendpolicies"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "cloud.google.com", Version: "v1", Resource: "backendconfigs"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "elbv2.k8s.aws", Version: "v1beta1", Resource: "ingressclassparams"}, namespaced: false},
	{gvr: schema.GroupVersionResource{Group: "gateway.k8s.aws", Version: "v1beta1", Resource: "loadbalancerconfigurations"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.k8s.aws", Version: "v1beta1", Resource: "targetgroupconfigurations"}, namespaced: true},
}

func (c *Collector) CollectExposureObjects(ctx context.Context, opts Options) (exposure.Objects, error) {
	objects, _, err := c.CollectExposureObjectsWithWarnings(ctx, opts)
	return objects, err
}

func (c *Collector) CollectExposureObjectsWithWarnings(ctx context.Context, opts Options) (exposure.Objects, []string, error) {
	if c == nil || c.Client == nil {
		return exposure.Objects{}, nil, nil
	}
	namespaces, err := namespacesForCollection(opts)
	if err != nil {
		return exposure.Objects{}, nil, err
	}

	objects := exposure.Objects{}
	var warnings []string
	for _, namespace := range namespaces {
		services, err := c.Client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return exposure.Objects{}, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("exposure analysis skipped Services in namespace %q: %v", namespace, err))
		} else {
			for _, svc := range services.Items {
				if isExcludedNamespace(svc.Namespace, opts.ExcludeNamespaces) {
					continue
				}
				objects.Services = append(objects.Services, svc)
			}
		}

		ingresses, err := c.Client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return exposure.Objects{}, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("exposure analysis skipped Ingresses in namespace %q: %v", namespace, err))
		} else {
			for _, ing := range ingresses.Items {
				if isExcludedNamespace(ing.Namespace, opts.ExcludeNamespaces) {
					continue
				}
				objects.Ingresses = append(objects.Ingresses, ing)
			}
		}
	}

	classes, err := c.Client.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return exposure.Objects{}, nil, ctxErr
		}
		warnings = append(warnings, fmt.Sprintf("exposure analysis skipped IngressClasses: %v", err))
	} else {
		objects.IngressClasses = append([]networkingv1.IngressClass(nil), classes.Items...)
	}

	if c.Dynamic == nil {
		return objects, warnings, nil
	}
	unstructuredObjects, dynamicWarnings := c.collectUnstructuredExposureObjects(ctx, namespaces, opts)
	warnings = append(warnings, dynamicWarnings...)
	objects.Unstructured = unstructuredObjects
	// Scoped collection can miss cross-namespace routes. An absent optional
	// CRD is fine, but authorization/discovery warnings preclude negatives.
	objects.CollectionComplete = len(warnings) == 0 && ctx.Err() == nil && opts.AllNamespaces && len(opts.ExcludeNamespaces) == 0
	return objects, warnings, nil
}

func (c *Collector) collectUnstructuredExposureObjects(ctx context.Context, namespaces []string, opts Options) ([]unstructured.Unstructured, []string) {
	var objects []unstructured.Unstructured
	var warnings []string
	for _, resource := range exposureResources {
		scopes := []string{""}
		if resource.namespaced {
			scopes = namespaces
		}
		// The first served version sticks for the remaining namespaces; a
		// resource served at no version is an absent optional CRD.
		versions := append([]string{resource.gvr.Version}, resource.fallbackVersions...)
		for _, namespace := range scopes {
			for len(versions) > 0 {
				gvr := resource.gvr
				gvr.Version = versions[0]
				items, warning, served := listUnstructured(ctx, c.Dynamic, gvr, namespace, opts)
				if !served {
					versions = versions[1:]
					continue
				}
				if warning != "" {
					warnings = append(warnings, warning)
				}
				objects = append(objects, items...)
				break
			}
			if len(versions) == 0 {
				break
			}
		}
	}
	return objects, warnings
}

// listUnstructured reports served=false when the API server does not serve the
// resource at gvr's version.
func listUnstructured(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, namespace string, opts Options) ([]unstructured.Unstructured, string, bool) {
	var resource dynamic.ResourceInterface
	if namespace == "" {
		resource = client.Resource(gvr)
	} else {
		resource = client.Resource(gvr).Namespace(namespace)
	}
	list, err := resource.List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, "", false
		}
		return nil, fmt.Sprintf("exposure analysis skipped optional resource %s in namespace %q: %v", gvr.String(), namespace, err), true
	}
	var filtered []unstructured.Unstructured
	for _, item := range list.Items {
		if isExcludedNamespace(item.GetNamespace(), opts.ExcludeNamespaces) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered, "", true
}
