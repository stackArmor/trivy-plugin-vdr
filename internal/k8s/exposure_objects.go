package k8s

import (
	"context"
	"fmt"
	"strings"

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
			warnings = append(warnings, fmt.Sprintf("exposure analysis skipped Services in namespace %q: %s", namespace, describeAPIError(err)))
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
			warnings = append(warnings, fmt.Sprintf("exposure analysis skipped Ingresses in namespace %q: %s", namespace, describeAPIError(err)))
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
		warnings = append(warnings, fmt.Sprintf("exposure analysis skipped IngressClasses: %s", describeAPIError(err)))
	} else {
		objects.IngressClasses = append([]networkingv1.IngressClass(nil), classes.Items...)
	}

	if c.Dynamic == nil {
		return objects, warnings, nil
	}
	unstructuredObjects, dynamicWarnings, ignoredRouteWarnings := c.collectUnstructuredExposureObjects(ctx, namespaces, opts)
	warnings = append(warnings, dynamicWarnings...)
	objects.Unstructured = unstructuredObjects
	objects.IgnoredRouteWarnings = ignoredRouteWarnings
	// Scoped collection can miss cross-namespace routes. An absent optional
	// CRD is fine, but authorization/discovery warnings preclude negatives.
	objects.CollectionComplete = len(warnings) == 0 && ctx.Err() == nil && opts.AllNamespaces && len(opts.ExcludeNamespaces) == 0
	return objects, warnings, nil
}

// describeAPIError labels authentication and authorization failures so they
// stand out in build logs.
func describeAPIError(err error) string {
	switch {
	case apierrors.IsUnauthorized(err):
		return fmt.Sprintf("authentication failed (HTTP 401 Unauthorized): %v", err)
	case apierrors.IsForbidden(err):
		return fmt.Sprintf("permission denied (HTTP 403 Forbidden): %v", err)
	}
	return err.Error()
}

// gatewayRouteKinds maps Gateway API route resources to their kinds.
var gatewayRouteKinds = map[string]string{
	"httproutes": "HTTPRoute",
	"grpcroutes": "GRPCRoute",
	"tcproutes":  "TCPRoute",
	"tlsroutes":  "TLSRoute",
	"udproutes":  "UDPRoute",
}

// listenerProtocolRouteKinds lists the route kinds each standard Gateway
// listener protocol accepts.
var listenerProtocolRouteKinds = map[string][]string{
	"HTTP":  {"HTTPRoute", "GRPCRoute"},
	"HTTPS": {"HTTPRoute", "GRPCRoute"},
	"TLS":   {"TLSRoute"},
	"TCP":   {"TCPRoute"},
	"UDP":   {"UDPRoute"},
}

func (c *Collector) collectUnstructuredExposureObjects(ctx context.Context, namespaces []string, opts Options) ([]unstructured.Unstructured, []string, []string) {
	var objects []unstructured.Unstructured
	var warnings []string
	// A forbidden route list only matters when a Gateway listener could accept
	// that route kind; it is held back until the Gateways are known.
	forbiddenRoutes := map[string][]string{}
	gatewaysComplete := true
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
				items, served, err := listUnstructured(ctx, c.Dynamic, gvr, namespace, opts)
				if !served {
					versions = versions[1:]
					continue
				}
				if err != nil {
					warning := fmt.Sprintf("exposure analysis skipped optional resource %s in namespace %q: %s", gvr.String(), namespace, describeAPIError(err))
					if kind, isRoute := gatewayRouteKinds[resource.gvr.Resource]; isRoute && apierrors.IsForbidden(err) {
						forbiddenRoutes[kind] = append(forbiddenRoutes[kind], warning)
					} else {
						if resource.gvr.Resource == "gateways" {
							gatewaysComplete = false
						}
						warnings = append(warnings, warning)
					}
				}
				objects = append(objects, items...)
				break
			}
			if len(versions) == 0 {
				break
			}
		}
	}

	var ignored []string
	accepted := acceptedRouteKinds(objects)
	for _, kind := range []string{"HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute", "UDPRoute"} {
		if !gatewaysComplete || accepted[kind] {
			warnings = append(warnings, forbiddenRoutes[kind]...)
		} else {
			ignored = append(ignored, forbiddenRoutes[kind]...)
		}
	}
	return objects, warnings, ignored
}

// acceptedRouteKinds returns the route kinds any collected Gateway listener can
// accept, from its protocol and any explicit allowedRoutes kinds. A listener
// with a non-standard protocol is assumed to accept every route kind.
func acceptedRouteKinds(objects []unstructured.Unstructured) map[string]bool {
	accepted := map[string]bool{}
	for _, object := range objects {
		if object.GetKind() != "Gateway" || !strings.HasPrefix(object.GetAPIVersion(), "gateway.networking.k8s.io/") {
			continue
		}
		listeners, _, _ := unstructured.NestedSlice(object.Object, "spec", "listeners")
		for _, raw := range listeners {
			listener, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			protocol, _, _ := unstructured.NestedString(listener, "protocol")
			kinds, standard := listenerProtocolRouteKinds[strings.ToUpper(protocol)]
			if !standard {
				for _, kind := range gatewayRouteKinds {
					accepted[kind] = true
				}
				continue
			}
			for _, kind := range kinds {
				accepted[kind] = true
			}
			allowed, _, _ := unstructured.NestedSlice(listener, "allowedRoutes", "kinds")
			for _, rawKind := range allowed {
				if entry, ok := rawKind.(map[string]any); ok {
					if kind, _, _ := unstructured.NestedString(entry, "kind"); kind != "" {
						accepted[kind] = true
					}
				}
			}
		}
	}
	return accepted
}

// listUnstructured reports served=false when the API server does not serve the
// resource at gvr's version.
func listUnstructured(ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource, namespace string, opts Options) ([]unstructured.Unstructured, bool, error) {
	var resource dynamic.ResourceInterface
	if namespace == "" {
		resource = client.Resource(gvr)
	} else {
		resource = client.Resource(gvr).Namespace(namespace)
	}
	list, err := resource.List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	var filtered []unstructured.Unstructured
	for _, item := range list.Items {
		if isExcludedNamespace(item.GetNamespace(), opts.ExcludeNamespaces) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered, true, nil
}
