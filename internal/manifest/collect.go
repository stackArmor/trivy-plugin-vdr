package manifest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/exposure"
	"github.com/stackArmor/trivy-plugin-vdr/internal/k8s"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/registry"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/fake"
)

// Document is one rendered manifest stream. DefaultNamespace is applied to the
// known namespaced object kinds that omit metadata.namespace, matching the
// namespace Helm would use when submitting those objects to Kubernetes.
type Document struct {
	Name             string
	YAML             []byte
	DefaultNamespace string
}

type Options struct {
	ContextName        string
	ClusterDefaults    map[string]string
	CollectPullSecrets bool
}

type Result struct {
	Inventory       *model.Inventory
	ExposureObjects exposure.Objects
	PullSecretAuths map[string]registry.DockerAuth
	Warnings        []string
}

type parsedObject struct {
	source string
	object unstructured.Unstructured
}

// Collect builds the same Kubernetes inventory used by a live-cluster scan,
// but from rendered objects. The client-go fake stores are used only as an
// in-memory typed object index; no Kubernetes configuration or API connection
// is opened.
func Collect(ctx context.Context, documents []Document, opts Options, logger *log.Logger) (Result, error) {
	parsed, err := parseDocuments(documents)
	if err != nil {
		return Result{}, err
	}

	runtimeObjects := make([]runtime.Object, 0, len(parsed))
	unstructuredObjects := make([]unstructured.Unstructured, 0, len(parsed))
	for _, item := range parsed {
		unstructuredObjects = append(unstructuredObjects, item.object)
		object, supported, err := toTypedObject(item.object)
		if err != nil {
			return Result{}, fmt.Errorf("decode %s %s from %s: %w", item.object.GetKind(), objectName(item.object), item.source, err)
		}
		if supported {
			runtimeObjects = append(runtimeObjects, object)
		}
	}

	client := fake.NewSimpleClientset(runtimeObjects...)
	collector := &k8s.Collector{Client: client, ContextName: opts.ContextName}
	k8sOptions := k8s.Options{AllNamespaces: true, IncludeZeroDaemonSets: true}
	inventory, err := collector.Collect(ctx, k8sOptions)
	if err != nil {
		return Result{}, fmt.Errorf("collect rendered Kubernetes inventory: %w", err)
	}
	if opts.ClusterDefaults != nil {
		inventory.ClusterDefaults = copyStringMap(opts.ClusterDefaults)
		inventory.Warnings = withoutClusterConfigMapWarning(inventory.Warnings)
	}

	objects, exposureWarnings, err := collector.CollectExposureObjectsWithWarnings(ctx, k8sOptions)
	if err != nil {
		return Result{}, fmt.Errorf("collect rendered exposure objects: %w", err)
	}
	objects.Unstructured = unstructuredObjects
	objects.InternetAccessibleIngressClasses, objects.InternetAccessibleGatewayClasses =
		exposure.ClassOverridesFromConfigMap(inventory.ClusterDefaults)

	warnings := append([]string(nil), inventory.Warnings...)
	warnings = append(warnings, exposureWarnings...)
	var pullSecretAuths map[string]registry.DockerAuth
	if opts.CollectPullSecrets {
		pullSecretAuths, exposureWarnings, err = collector.CollectPullSecretAuths(ctx, k8sOptions, logger)
		if err != nil {
			return Result{}, fmt.Errorf("collect rendered pull secrets: %w", err)
		}
		warnings = append(warnings, exposureWarnings...)
	}

	return Result{
		Inventory:       inventory,
		ExposureObjects: objects,
		PullSecretAuths: pullSecretAuths,
		Warnings:        warnings,
	}, nil
}

// LoadConfigMap reads exactly one ConfigMap manifest and returns its data for
// the existing VDR cluster-default/scoring path. The ConfigMap may use any name
// or namespace because the explicit flag identifies its purpose.
func LoadConfigMap(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ConfigMap %q: %w", path, err)
	}
	parsed, err := parseDocuments([]Document{{Name: path, YAML: data}})
	if err != nil {
		return nil, err
	}
	var found *unstructured.Unstructured
	for i := range parsed {
		if parsed[i].object.GetAPIVersion() != "v1" || parsed[i].object.GetKind() != "ConfigMap" {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("ConfigMap file %q contains more than one ConfigMap", path)
		}
		copy := parsed[i].object
		found = &copy
	}
	if found == nil {
		return nil, fmt.Errorf("ConfigMap file %q does not contain a v1 ConfigMap", path)
	}
	values, foundData, err := unstructured.NestedStringMap(found.Object, "data")
	if err != nil {
		return nil, fmt.Errorf("ConfigMap %s data must contain string values: %w", objectName(*found), err)
	}
	if !foundData || len(values) == 0 {
		return nil, fmt.Errorf("ConfigMap %s has no data", objectName(*found))
	}
	return values, nil
}

func parseDocuments(documents []Document) ([]parsedObject, error) {
	var result []parsedObject
	seen := map[string]string{}
	for _, document := range documents {
		decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(document.YAML), 4096)
		for index := 1; ; index++ {
			var object unstructured.Unstructured
			if err := decoder.Decode(&object); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("decode %s document %d: %w", document.Name, index, err)
			}
			if len(object.Object) == 0 {
				continue
			}
			objects, err := flattenObject(object)
			if err != nil {
				return nil, fmt.Errorf("decode %s document %d: %w", document.Name, index, err)
			}
			for _, item := range objects {
				if item.GetAPIVersion() == "" || item.GetKind() == "" {
					return nil, fmt.Errorf("decode %s document %d: apiVersion and kind are required", document.Name, index)
				}
				if item.GetName() == "" {
					return nil, fmt.Errorf("decode %s document %d: metadata.name is required for %s", document.Name, index, item.GetKind())
				}
				gvk := item.GroupVersionKind()
				if item.GetNamespace() == "" && isKnownNamespaced(gvk) {
					item.SetNamespace(document.DefaultNamespace)
				}
				key := objectKey(item)
				if previous, ok := seen[key]; ok {
					return nil, fmt.Errorf("duplicate rendered object %s in %s and %s", key, previous, document.Name)
				}
				seen[key] = document.Name
				result = append(result, parsedObject{source: document.Name, object: item})
			}
		}
	}
	return result, nil
}

func flattenObject(object unstructured.Unstructured) ([]unstructured.Unstructured, error) {
	if object.GetKind() != "List" {
		return []unstructured.Unstructured{object}, nil
	}
	items, found, err := unstructured.NestedSlice(object.Object, "items")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	result := make([]unstructured.Unstructured, 0, len(items))
	for _, raw := range items {
		values, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("List items must be Kubernetes objects")
		}
		result = append(result, unstructured.Unstructured{Object: values})
	}
	return result, nil
}

func toTypedObject(object unstructured.Unstructured) (runtime.Object, bool, error) {
	var target runtime.Object
	gvk := object.GroupVersionKind()
	switch {
	case gvk.Group == "" && gvk.Version == "v1":
		switch gvk.Kind {
		case "Namespace":
			target = &corev1.Namespace{}
		case "ConfigMap":
			target = &corev1.ConfigMap{}
		case "Secret":
			target = &corev1.Secret{}
		case "Pod":
			target = &corev1.Pod{}
		case "Service":
			target = &corev1.Service{}
		}
	case gvk.Group == "apps" && gvk.Version == "v1":
		switch gvk.Kind {
		case "Deployment":
			target = &appsv1.Deployment{}
		case "StatefulSet":
			target = &appsv1.StatefulSet{}
		case "DaemonSet":
			target = &appsv1.DaemonSet{}
		}
	case gvk.Group == "batch" && gvk.Version == "v1":
		switch gvk.Kind {
		case "Job":
			target = &batchv1.Job{}
		case "CronJob":
			target = &batchv1.CronJob{}
		}
	case gvk.Group == "networking.k8s.io" && gvk.Version == "v1":
		switch gvk.Kind {
		case "Ingress":
			target = &networkingv1.Ingress{}
		case "IngressClass":
			target = &networkingv1.IngressClass{}
		case "NetworkPolicy":
			target = &networkingv1.NetworkPolicy{}
		}
	case gvk.Group == "policy" && gvk.Version == "v1" && gvk.Kind == "PodDisruptionBudget":
		target = &policyv1.PodDisruptionBudget{}
	}
	if target == nil {
		return nil, false, nil
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, target); err != nil {
		return nil, true, err
	}
	return target, true, nil
}

func isKnownNamespaced(gvk schema.GroupVersionKind) bool {
	switch gvk.Group {
	case "":
		return gvk.Kind == "Pod" || gvk.Kind == "Service" || gvk.Kind == "ConfigMap" || gvk.Kind == "Secret" || gvk.Kind == "ServiceAccount"
	case "apps":
		return gvk.Kind == "Deployment" || gvk.Kind == "StatefulSet" || gvk.Kind == "DaemonSet" || gvk.Kind == "ReplicaSet"
	case "batch":
		return gvk.Kind == "Job" || gvk.Kind == "CronJob"
	case "networking.k8s.io":
		return gvk.Kind == "Ingress" || gvk.Kind == "NetworkPolicy"
	case "policy":
		return gvk.Kind == "PodDisruptionBudget"
	case "gateway.networking.k8s.io":
		return gvk.Kind != "GatewayClass"
	case "networking.gke.io", "cloud.google.com":
		return true
	case "elbv2.k8s.aws":
		return gvk.Kind != "IngressClassParams"
	case "gateway.k8s.aws":
		return true
	default:
		return false
	}
}

func objectKey(object unstructured.Unstructured) string {
	namespace := object.GetNamespace()
	if namespace == "" {
		namespace = "<cluster>"
	}
	return strings.Join([]string{object.GetAPIVersion(), object.GetKind(), namespace, object.GetName()}, "/")
}

func objectName(object unstructured.Unstructured) string {
	if object.GetNamespace() == "" {
		return object.GetName()
	}
	return object.GetNamespace() + "/" + object.GetName()
}

func copyStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

func withoutClusterConfigMapWarning(warnings []string) []string {
	result := warnings[:0]
	for _, warning := range warnings {
		if strings.HasPrefix(warning, "cluster FedRAMP ConfigMap ") {
			continue
		}
		result = append(result, warning)
	}
	return result
}
