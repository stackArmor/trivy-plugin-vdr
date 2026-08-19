package k8scompliance

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestControllerIndexMapsPodsAndJobsToTopLevelControllers(t *testing.T) {
	controller := true
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "api",
		UID:       types.UID("deployment-uid"),
	}}
	replicaSet := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "api-abc",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "api",
			UID:        types.UID("deployment-uid"),
			Controller: &controller,
		}},
	}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "api-abc-123",
		UID:       types.UID("pod-uid"),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
			Name:       "api-abc",
			Controller: &controller,
		}},
	}}
	cronJob := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "nightly",
		UID:       types.UID("cronjob-uid"),
	}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "nightly-123",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "batch/v1",
			Kind:       "CronJob",
			Name:       "nightly",
			UID:        types.UID("cronjob-uid"),
			Controller: &controller,
		}},
	}}
	client := fake.NewSimpleClientset(deployment, replicaSet, pod, cronJob, job)

	index, warnings := BuildControllerIndex(context.Background(), client, []string{"default"}, nil)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	resources := []ResourceReport{
		{Resource: ObjectRef{Namespace: "default", Kind: "Pod", Name: "api-abc-123"}},
		{Resource: ObjectRef{Namespace: "default", Kind: "Job", Name: "nightly-123"}},
		{Resource: ObjectRef{Namespace: "default", Kind: "Deployment", Name: "api"}},
	}
	index.Enrich(resources)

	if got := resources[0].Resource.UID; got != "pod-uid" {
		t.Fatalf("Pod UID = %q, want pod-uid", got)
	}
	if got := resources[0].ParentController; got == nil || got.Kind != "Deployment" || got.Name != "api" {
		t.Fatalf("Pod parent controller = %#v, want Deployment/api", got)
	}
	if got := resources[1].ParentController; got == nil || got.Kind != "CronJob" || got.Name != "nightly" {
		t.Fatalf("Job parent controller = %#v, want CronJob/nightly", got)
	}
	if resources[2].ParentController != nil {
		t.Fatalf("top-level Deployment parent controller = %#v, want nil", resources[2].ParentController)
	}
}

func TestBuildControllerIndexFiltersExcludedNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "kube-system"}},
	)
	index, warnings := BuildControllerIndex(context.Background(), client, nil, []string{"kube-system"})
	if len(warnings) > 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if _, ok := index.Lookup("v1", "Pod", "default", "pod-1"); !ok {
		t.Error("expected default/pod-1 to be indexed")
	}
	if _, ok := index.Lookup("v1", "Pod", "kube-system", "pod-2"); ok {
		t.Error("expected kube-system/pod-2 to NOT be indexed")
	}
}
