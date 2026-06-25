package k8s

import (
	"context"
	"fmt"

	"github.com/matthewvenne/trivy-plugin-vdr/internal/exposure"
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
}

var exposureResources = []exposureResource{
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tcproutes"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tlsroutes"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "referencegrants"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "networking.gke.io", Version: "v1", Resource: "gcpbackendpolicies"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "cloud.google.com", Version: "v1", Resource: "backendconfigs"}, namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "elbv2.k8s.aws", Version: "v1beta1", Resource: "ingressclassparams"}, namespaced: false},
	{gvr: schema.GroupVersionResource{Group: "gateway.k8s.aws", Version: "v1beta1", Resource: "loadbalancerconfigurations"}, namespaced: true},
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
			objects.Services = append(objects.Services, services.Items...)
		}

		ingresses, err := c.Client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return exposure.Objects{}, nil, ctxErr
			}
			warnings = append(warnings, fmt.Sprintf("exposure analysis skipped Ingresses in namespace %q: %v", namespace, err))
		} else {
			objects.Ingresses = append(objects.Ingresses, ingresses.Items...)
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
	unstructuredObjects, dynamicWarnings := c.collectUnstructuredExposureObjects(ctx, namespaces)
	warnings = append(warnings, dynamicWarnings...)
	objects.Unstructured = unstructuredObjects
	return objects, warnings, nil
}

func (c *Collector) collectUnstructuredExposureObjects(ctx context.Context, namespaces []string) ([]unstructured.Unstructured, []string) {
	var objects []unstructured.Unstructured
	var warnings []string
	for _, resource := range exposureResources {
		if resource.namespaced {
			for _, namespace := range namespaces {
				items, warning := listUnstructured(ctx, c.Dynamic, resource.gvr, namespace)
				if warning != "" {
					warnings = append(warnings, warning)
				}
				objects = append(objects, items...)
			}
			continue
		}
		items, warning := listUnstructured(ctx, c.Dynamic, resource.gvr, "")
		if warning != "" {
			warnings = append(warnings, warning)
		}
		objects = append(objects, items...)
	}
	return objects, warnings
}

func listUnstructured(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, namespace string) ([]unstructured.Unstructured, string) {
	var resource dynamic.ResourceInterface
	if namespace == "" {
		resource = client.Resource(gvr)
	} else {
		resource = client.Resource(gvr).Namespace(namespace)
	}
	list, err := resource.List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ""
		}
		return nil, fmt.Sprintf("exposure analysis skipped optional resource %s in namespace %q: %v", gvr.String(), namespace, err)
	}
	return list.Items, ""
}
