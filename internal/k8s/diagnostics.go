package k8s

import (
	"context"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/diagnostics"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CollectDiagnostics adds bounded supporting reads to the exact GET snapshots
// captured by the diagnostic transport. It uses the caller's existing access;
// unavailable/forbidden resources are recorded by the transport and skipped.
func (c *Collector) CollectDiagnostics(ctx context.Context, opts Options, bundle *diagnostics.Bundle) {
	if c == nil || c.Client == nil || c.Dynamic == nil {
		bundle.Note("supporting-reads", "dynamic Kubernetes client unavailable")
		return
	}
	namespaces, err := namespacesForCollection(opts)
	if err != nil {
		bundle.Note("supporting-reads", "invalid namespace scope")
		return
	}
	resources := []exposureResource{
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "pods"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "events"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "services"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "replicationcontrollers"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "resourcequotas"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "limitranges"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "nodes"}},
		{gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingressclasses"}},
		{gvr: schema.GroupVersionResource{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "discovery.k8s.io", Version: "v1", Resource: "endpointslices"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}, namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}},
		{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}},
	}
	resources = append(resources, exposureResources...)
	resources = append(resources, exposureResource{gvr: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}})
	// The shared budget prevents restricted or unreachable API endpoints from
	// delaying the customer's scan indefinitely. Each call also has a deadline.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	versionCtx, versionCancel := context.WithTimeout(ctx, 10*time.Second)
	_, _ = c.Client.Discovery().RESTClient().Get().AbsPath("/version").DoRaw(versionCtx)
	versionCancel()
	for _, resource := range resources {
		scopes := []string{""}
		if resource.namespaced {
			scopes = namespaces
		}
		for _, namespace := range scopes {
			if ctx.Err() != nil {
				bundle.Note("supporting-reads", "collection deadline or cancellation reached; remaining supporting reads omitted")
				return
			}
			versions := append([]string{resource.gvr.Version}, resource.fallbackVersions...)
			for _, version := range versions {
				gvr := resource.gvr
				gvr.Version = version
				callCtx, callCancel := context.WithTimeout(ctx, 10*time.Second)
				served, err := listDiagnosticPages(callCtx, c, gvr, namespace)
				callCancel()
				if err != nil || served {
					break
				}
			}
		}
	}
}

// Pagination keeps each response small while retaining all accessible items.
func listDiagnosticPages(ctx context.Context, c *Collector, gvr schema.GroupVersionResource, namespace string) (bool, error) {
	client := c.Dynamic.Resource(gvr).Namespace(namespace)
	opts := metav1.ListOptions{Limit: 250}
	for {
		list, err := client.List(ctx, opts)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return true, err
		}
		opts.Continue = list.GetContinue()
		if opts.Continue == "" {
			return true, nil
		}
	}
}
