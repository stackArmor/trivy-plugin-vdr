package k8s

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCollectPodRuntimeIssuesReportsImagePullFailures(t *testing.T) {
	controller := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod",
			Name:      "api-123",
			OwnerReferences: []metav1.OwnerReference{{
				Kind: "ReplicaSet", Name: "api-abc", Controller: &controller,
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			InitContainerStatuses: []corev1.ContainerStatus{{
				Name: "migrate", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason: "ErrImagePull", Message: "pull access denied",
				}},
			}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "api", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason: "ImagePullBackOff", Message: "back-off pulling image",
				}},
			}},
		},
	}
	issues, err := (&Collector{Client: fake.NewSimpleClientset(pod)}).CollectPodRuntimeIssues(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("CollectPodRuntimeIssues() error = %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("issues = %#v, want two image-pull failures without duplicate Pending issue", issues)
	}
	if issues[0].Workload != "ReplicaSet/api-abc" || issues[0].Container != "api" || issues[0].Reason != "ImagePullBackOff" {
		t.Fatalf("issues[0] = %#v", issues[0])
	}
	if issues[1].Container != "migrate" || issues[1].Reason != "ErrImagePull" || issues[1].Message != "pull access denied" {
		t.Fatalf("issues[1] = %#v", issues[1])
	}
}

func TestCollectPodRuntimeIssuesReportsPendingPod(t *testing.T) {
	since := metav1.NewTime(time.Date(2026, time.August, 6, 14, 30, 0, 0, time.UTC))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "unschedulable"},
		Status: corev1.PodStatus{
			Phase:   corev1.PodPending,
			Reason:  "Unschedulable",
			Message: "0/3 nodes are available",
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodScheduled, LastTransitionTime: since,
			}},
		},
	}
	issues, err := (&Collector{Client: fake.NewSimpleClientset(pod)}).CollectPodRuntimeIssues(context.Background(), Options{Namespaces: []string{"prod"}})
	if err != nil {
		t.Fatalf("CollectPodRuntimeIssues() error = %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("issues = %#v, want one Pending issue", issues)
	}
	issue := issues[0]
	if issue.Workload != "Pod/unschedulable" || issue.Reason != "Unschedulable" || issue.Since != "2026-08-06T14:30:00Z" {
		t.Fatalf("issue = %#v", issue)
	}
}

func TestCollectPodRuntimeIssuesWithExcludeNamespaces(t *testing.T) {
	podExcluded := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-excluded", Namespace: "kube-system"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "agent",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "failed to pull"},
					},
				},
			},
		},
	}
	client := fake.NewSimpleClientset(podExcluded)
	collector := &Collector{Client: client}
	issues, err := collector.CollectPodRuntimeIssues(context.Background(), Options{
		AllNamespaces:     true,
		ExcludeNamespaces: []string{"kube-system"},
	})
	if err != nil {
		t.Fatalf("CollectPodRuntimeIssues() error = %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("expected 0 issues due to namespace exclusion, got %d", len(issues))
	}
}

