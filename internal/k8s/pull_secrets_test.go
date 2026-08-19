package k8s

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
)

func dockerConfigJSONSecret(namespace, name, host, user, pass string) *corev1.Secret {
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	body := `{"auths":{"` + host + `":{"auth":"` + auth + `"}}}`
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(body)},
	}
}

func podWithPullSecret(namespace, name, secretName string) *corev1.Pod {
	p := pod(namespace, name, podSpec(container("app", "registry.example.com/app:v1")))
	p.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: secretName}}
	return p
}

func TestCollectPullSecretAuths(t *testing.T) {
	client := fake.NewSimpleClientset(
		podWithPullSecret("default", "web", "regcred"),
		dockerConfigJSONSecret("default", "regcred", "registry.example.com", "user", "pass"),
	)

	auths, warnings, err := (&Collector{Client: client}).CollectPullSecretAuths(context.Background(), Options{AllNamespaces: true}, nil)
	if err != nil {
		t.Fatalf("CollectPullSecretAuths error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	entry, ok := auths["registry.example.com"]
	if !ok {
		t.Fatalf("missing auth for registry.example.com: %v", auths)
	}
	if entry.Username != "user" || entry.Password != "pass" {
		t.Fatalf("unexpected auth: %+v", entry)
	}
}

func TestCollectPullSecretAuthsLegacyDockercfg(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("AWS:tok"))
	body := `{"123456789012.dkr.ecr.us-east-1.amazonaws.com":{"auth":"` + auth + `"}}`
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ecrcred"},
		Type:       corev1.SecretTypeDockercfg,
		Data:       map[string][]byte{corev1.DockerConfigKey: []byte(body)},
	}
	client := fake.NewSimpleClientset(podWithPullSecret("default", "web", "ecrcred"), secret)

	auths, _, err := (&Collector{Client: client}).CollectPullSecretAuths(context.Background(), Options{AllNamespaces: true}, nil)
	if err != nil {
		t.Fatalf("CollectPullSecretAuths error: %v", err)
	}
	if _, ok := auths["123456789012.dkr.ecr.us-east-1.amazonaws.com"]; !ok {
		t.Fatalf("missing legacy dockercfg auth: %v", auths)
	}
}

func TestCollectPullSecretAuthsMissingSecretWarns(t *testing.T) {
	client := fake.NewSimpleClientset(podWithPullSecret("default", "web", "absent"))

	auths, warnings, err := (&Collector{Client: client}).CollectPullSecretAuths(context.Background(), Options{AllNamespaces: true}, nil)
	if err != nil {
		t.Fatalf("CollectPullSecretAuths error: %v", err)
	}
	if len(auths) != 0 {
		t.Fatalf("expected no auths, got %v", auths)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "absent") {
		t.Fatalf("expected warning about missing secret, got %v", warnings)
	}
}

func TestCollectPullSecretAuthsForbiddenWarns(t *testing.T) {
	client := fake.NewSimpleClientset(podWithPullSecret("default", "web", "regcred"))
	client.PrependReactor("get", "secrets", func(action clientgotesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "regcred", nil)
	})

	_, warnings, err := (&Collector{Client: client}).CollectPullSecretAuths(context.Background(), Options{AllNamespaces: true}, nil)
	if err != nil {
		t.Fatalf("CollectPullSecretAuths error = %v, want nil for forbidden secret", err)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "forbidden") {
		t.Fatalf("expected forbidden warning, got %v", warnings)
	}
}

func TestCollectPullSecretAuthsCanceledContext(t *testing.T) {
	client := fake.NewSimpleClientset(podWithPullSecret("default", "web", "regcred"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := (&Collector{Client: client}).CollectPullSecretAuths(ctx, Options{AllNamespaces: true}, nil)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestCollectPullSecretAuthsExcludeNamespaces(t *testing.T) {
	depDefault := deployment("default", "deploy-default", podSpec(container("web", "web:latest")))
	depDefault.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "regcred-deploy"}}

	depExcluded := deployment("kube-system", "deploy-excluded", podSpec(container("coredns", "coredns:latest")))
	depExcluded.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "missing-sys-dep-secret"}}

	stsExcluded := statefulSet("kube-system", "sts-excluded", podSpec(container("kube-db", "kube-db:latest")))
	stsExcluded.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "missing-sys-sts-secret"}}

	dsExcluded := daemonSet("kube-system", "ds-excluded", 1, podSpec(container("kube-proxy", "kube-proxy:latest")))
	dsExcluded.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "missing-sys-ds-secret"}}

	jobExcluded := job("kube-system", "job-excluded", podSpec(container("kube-bench", "kube-bench:latest")))
	jobExcluded.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "missing-sys-job-secret"}}

	cronExcluded := cronJob("kube-system", "cron-excluded", podSpec(container("kube-cleanup", "kube-cleanup:latest")))
	cronExcluded.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "missing-sys-cron-secret"}}

	client := fake.NewSimpleClientset(
		podWithPullSecret("default", "pod-default", "regcred-pod"),
		dockerConfigJSONSecret("default", "regcred-pod", "registry.default.example.com", "user1", "pass1"),
		depDefault,
		dockerConfigJSONSecret("default", "regcred-deploy", "registry-deploy.default.example.com", "user2", "pass2"),
		podWithPullSecret("kube-system", "pod-excluded", "regcred-sys-pod"),
		dockerConfigJSONSecret("kube-system", "regcred-sys-pod", "registry.system.example.com", "sysuser", "syspass"),
		depExcluded,
		stsExcluded,
		dsExcluded,
		jobExcluded,
		cronExcluded,
	)

	auths, warnings, err := (&Collector{Client: client}).CollectPullSecretAuths(
		context.Background(),
		Options{
			AllNamespaces:     true,
			ExcludeNamespaces: []string{"kube-system"},
		},
		nil,
	)
	if err != nil {
		t.Fatalf("CollectPullSecretAuths error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings from excluded namespace resources: %v", warnings)
	}
	if _, ok := auths["registry.default.example.com"]; !ok {
		t.Errorf("missing auth for registry.default.example.com")
	}
	if _, ok := auths["registry-deploy.default.example.com"]; !ok {
		t.Errorf("missing auth for registry-deploy.default.example.com")
	}
	if _, ok := auths["registry.system.example.com"]; ok {
		t.Errorf("unexpected auth for registry.system.example.com from excluded namespace")
	}
}
