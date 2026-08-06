package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodRuntimeIssue is an actionable runtime condition observed on a workload
// pod. It is intentionally separate from inventory: a workload can be valid
// for image scanning even while one of its running pods cannot start.
type PodRuntimeIssue struct {
	Namespace string
	Pod       string
	Workload  string
	Container string
	Reason    string
	Message   string
	Since     string
}

// CollectPodRuntimeIssues returns image-pull failures and Pending pods in the
// requested namespaces. It reads only Pod status and does not affect inventory
// or scan results.
func (c *Collector) CollectPodRuntimeIssues(ctx context.Context, opts Options) ([]PodRuntimeIssue, error) {
	if c == nil || c.Client == nil {
		return nil, fmt.Errorf("kubernetes collector requires a client")
	}

	namespaces, err := namespacesForCollection(opts)
	if err != nil {
		return nil, err
	}

	var issues []PodRuntimeIssue
	for _, namespace := range namespaces {
		pods, err := c.Client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for i := range pods.Items {
			issues = append(issues, podRuntimeIssues(&pods.Items[i])...)
		}
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Namespace != issues[j].Namespace {
			return issues[i].Namespace < issues[j].Namespace
		}
		if issues[i].Pod != issues[j].Pod {
			return issues[i].Pod < issues[j].Pod
		}
		return issues[i].Container < issues[j].Container
	})
	return issues, nil
}

func podRuntimeIssues(pod *corev1.Pod) []PodRuntimeIssue {
	workload := podWorkload(pod)
	statuses := append([]corev1.ContainerStatus(nil), pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)

	var issues []PodRuntimeIssue
	hasImagePullFailure := false
	for _, status := range statuses {
		if status.State.Waiting == nil || !isImagePullFailure(status.State.Waiting.Reason) {
			continue
		}
		hasImagePullFailure = true
		issues = append(issues, PodRuntimeIssue{
			Namespace: pod.Namespace,
			Pod:       pod.Name,
			Workload:  workload,
			Container: status.Name,
			Reason:    status.State.Waiting.Reason,
			Message:   status.State.Waiting.Message,
		})
	}

	// Image-pull failures normally leave a pod Pending. Reporting the pull
	// failure alone is more useful and avoids a duplicate warning for the same
	// underlying problem.
	if pod.Status.Phase == corev1.PodPending && !hasImagePullFailure {
		issue := PodRuntimeIssue{
			Namespace: pod.Namespace,
			Pod:       pod.Name,
			Workload:  workload,
			Reason:    pod.Status.Reason,
			Message:   pod.Status.Message,
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodScheduled || condition.Type == corev1.PodReady {
				if !condition.LastTransitionTime.IsZero() {
					issue.Since = condition.LastTransitionTime.UTC().Format("2006-01-02T15:04:05Z")
				}
				break
			}
		}
		issues = append(issues, issue)
	}
	return issues
}

func isImagePullFailure(reason string) bool {
	switch strings.ToLower(reason) {
	case "imagepullbackoff", "errimagepull", "imagepullerr":
		return true
	default:
		return false
	}
}

func podWorkload(pod *corev1.Pod) string {
	for _, owner := range pod.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			return fmt.Sprintf("%s/%s", owner.Kind, owner.Name)
		}
	}
	return fmt.Sprintf("Pod/%s", pod.Name)
}
