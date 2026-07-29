package k8scompliance

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type objectKey struct {
	namespace string
	kind      string
	name      string
}

type indexedObject struct {
	ref   ObjectRef
	owner *ObjectRef
}

type ControllerIndex struct {
	objects map[objectKey]indexedObject
}

func BuildControllerIndex(ctx context.Context, client kubernetes.Interface, namespaces []string) (*ControllerIndex, []string) {
	index := &ControllerIndex{objects: map[objectKey]indexedObject{}}
	if client == nil {
		return index, []string{"parent-controller mapping was skipped because the Kubernetes client is unavailable"}
	}
	scopes := namespaces
	if len(scopes) == 0 {
		scopes = []string{metav1.NamespaceAll}
	}
	var warnings []string
	for _, namespace := range scopes {
		if list, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{}); err != nil {
			warnings = appendListWarning(warnings, namespace, "Pods", err)
		} else {
			for i := range list.Items {
				index.add(&list.Items[i], "v1", "Pod")
			}
		}
		if list, err := client.CoreV1().ReplicationControllers(namespace).List(ctx, metav1.ListOptions{}); err != nil {
			warnings = appendListWarning(warnings, namespace, "ReplicationControllers", err)
		} else {
			for i := range list.Items {
				index.add(&list.Items[i], "v1", "ReplicationController")
			}
		}
		if list, err := client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{}); err != nil {
			warnings = appendListWarning(warnings, namespace, "Deployments", err)
		} else {
			for i := range list.Items {
				index.add(&list.Items[i], "apps/v1", "Deployment")
			}
		}
		if list, err := client.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{}); err != nil {
			warnings = appendListWarning(warnings, namespace, "ReplicaSets", err)
		} else {
			for i := range list.Items {
				index.add(&list.Items[i], "apps/v1", "ReplicaSet")
			}
		}
		if list, err := client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{}); err != nil {
			warnings = appendListWarning(warnings, namespace, "StatefulSets", err)
		} else {
			for i := range list.Items {
				index.add(&list.Items[i], "apps/v1", "StatefulSet")
			}
		}
		if list, err := client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{}); err != nil {
			warnings = appendListWarning(warnings, namespace, "DaemonSets", err)
		} else {
			for i := range list.Items {
				index.add(&list.Items[i], "apps/v1", "DaemonSet")
			}
		}
		if list, err := client.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{}); err != nil {
			warnings = appendListWarning(warnings, namespace, "Jobs", err)
		} else {
			for i := range list.Items {
				index.add(&list.Items[i], "batch/v1", "Job")
			}
		}
		if list, err := client.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{}); err != nil {
			warnings = appendListWarning(warnings, namespace, "CronJobs", err)
		} else {
			for i := range list.Items {
				index.add(&list.Items[i], "batch/v1", "CronJob")
			}
		}
	}
	return index, warnings
}

func (i *ControllerIndex) Enrich(resources []ResourceReport) {
	if i == nil {
		return
	}
	for resourceIndex := range resources {
		resource := &resources[resourceIndex]
		key := objectKey{
			namespace: resource.Resource.Namespace,
			kind:      strings.ToLower(resource.Resource.Kind),
			name:      resource.Resource.Name,
		}
		indexed, ok := i.objects[key]
		if !ok {
			continue
		}
		resource.Resource = indexed.ref
		if parent := i.parentController(key); parent != nil {
			resource.ParentController = parent
		}
	}
}

func (i *ControllerIndex) add(object metav1.Object, apiVersion, kind string) {
	ref := ObjectRef{
		APIVersion: apiVersion,
		Kind:       kind,
		Namespace:  object.GetNamespace(),
		Name:       object.GetName(),
		UID:        string(object.GetUID()),
	}
	var owner *ObjectRef
	for _, candidate := range object.GetOwnerReferences() {
		if candidate.Controller == nil || !*candidate.Controller {
			continue
		}
		owner = &ObjectRef{
			APIVersion: candidate.APIVersion,
			Kind:       candidate.Kind,
			Namespace:  object.GetNamespace(),
			Name:       candidate.Name,
			UID:        string(candidate.UID),
		}
		break
	}
	i.objects[objectKey{namespace: ref.Namespace, kind: strings.ToLower(ref.Kind), name: ref.Name}] = indexedObject{
		ref:   ref,
		owner: owner,
	}
}

func (i *ControllerIndex) parentController(key objectKey) *ObjectRef {
	seen := map[objectKey]bool{key: true}
	current, ok := i.objects[key]
	if !ok || current.owner == nil {
		return nil
	}
	parent := *current.owner
	for {
		parentKey := objectKey{namespace: parent.Namespace, kind: strings.ToLower(parent.Kind), name: parent.Name}
		if seen[parentKey] {
			return &parent
		}
		seen[parentKey] = true
		next, ok := i.objects[parentKey]
		if !ok {
			return &parent
		}
		parent = next.ref
		if next.owner == nil {
			return &parent
		}
		parent = *next.owner
	}
}

func appendListWarning(warnings []string, namespace, kind string, err error) []string {
	scope := namespace
	if scope == "" {
		scope = "all namespaces"
	} else {
		scope = "namespace " + scope
	}
	return append(warnings, fmt.Sprintf("could not list %s in %s for parent-controller mapping: %v", kind, scope, err))
}
