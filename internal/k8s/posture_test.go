package k8s

import (
	"context"
	"reflect"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestWorkloadPostureFromPodSpecAndNetworkPolicy exercises the read-only posture
// capture end-to-end: a hardened Deployment pod template plus a namespace
// NetworkPolicy and PodDisruptionBudget that select it. Every asserted field is a
// neutral Kubernetes fact (podspec value or raw NetworkPolicy CIDR), with no
// cloud-control/taxonomy/scoring interpretation.
func TestWorkloadPostureFromPodSpecAndNetworkPolicy(t *testing.T) {
	replicas := int32(3)
	deploy := deployment("prod", "api", posturePodSpec())
	deploy.Spec.Replicas = &replicas
	deploy.Spec.Template.Labels = map[string]string{"app": "api"}

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "api-egress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{IPBlock: &networkingv1.IPBlock{
							CIDR:   "10.0.0.0/8",
							Except: []string{"10.1.2.3/32"},
						}},
					},
				},
			},
		},
	}
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "api-pdb"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
		},
	}

	client := fake.NewSimpleClientset(deploy, np, pdb)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	posture := requirePosture(t, inv, "api")

	if posture.SecurityContext == nil {
		t.Fatalf("SecurityContext posture missing")
	}
	sc := posture.SecurityContext
	if !sc.ReadOnlyRootFilesystem {
		t.Errorf("ReadOnlyRootFilesystem = false, want true")
	}
	if !sc.RunAsNonRoot {
		t.Errorf("RunAsNonRoot = false, want true")
	}
	if sc.Privileged {
		t.Errorf("Privileged = true, want false")
	}
	if sc.AllowPrivilegeEscalation {
		t.Errorf("AllowPrivilegeEscalation = true, want false")
	}
	if !reflect.DeepEqual(sc.DroppedCapabilities, []string{"ALL"}) {
		t.Errorf("DroppedCapabilities = %#v, want [ALL]", sc.DroppedCapabilities)
	}
	if sc.SeccompProfileType != string(corev1.SeccompProfileTypeRuntimeDefault) {
		t.Errorf("SeccompProfileType = %q, want RuntimeDefault", sc.SeccompProfileType)
	}

	if posture.Workload == nil {
		t.Fatalf("Workload posture missing")
	}
	w := posture.Workload
	if w.Replicas == nil || *w.Replicas != 3 {
		t.Errorf("Replicas = %v, want 3", w.Replicas)
	}
	if !w.HasPodDisruptionBudget {
		t.Errorf("HasPodDisruptionBudget = false, want true")
	}
	if !w.ZoneSpread {
		t.Errorf("ZoneSpread = false, want true")
	}
	if !w.LivenessProbe {
		t.Errorf("LivenessProbe = false, want true")
	}
	if !w.ReadinessProbe {
		t.Errorf("ReadinessProbe = false, want true")
	}

	if posture.Identity == nil {
		t.Fatalf("Identity posture missing")
	}
	id := posture.Identity
	if id.ServiceAccountName != "api-sa" {
		t.Errorf("ServiceAccountName = %q, want api-sa", id.ServiceAccountName)
	}
	if id.AutomountServiceAccountToken == nil || *id.AutomountServiceAccountToken {
		t.Errorf("AutomountServiceAccountToken = %v, want false", id.AutomountServiceAccountToken)
	}
	if !id.EnvFromSecretRef {
		t.Errorf("EnvFromSecretRef = false, want true")
	}

	if posture.Volumes == nil {
		t.Fatalf("Volumes posture missing")
	}
	if !reflect.DeepEqual(posture.Volumes.WritableVolumeMounts, []string{"/data"}) {
		t.Errorf("WritableVolumeMounts = %#v, want [/data]", posture.Volumes.WritableVolumeMounts)
	}

	if posture.NetworkPolicy == nil {
		t.Fatalf("NetworkPolicy posture missing")
	}
	npf := posture.NetworkPolicy
	if !npf.SelectedByEgressPolicy {
		t.Errorf("SelectedByEgressPolicy = false, want true")
	}
	if !npf.SelectedByIngressPolicy {
		t.Errorf("SelectedByIngressPolicy = false, want true")
	}
	if npf.EgressDefaultDeny {
		t.Errorf("EgressDefaultDeny = true, want false (an allow rule is present)")
	}
	if !reflect.DeepEqual(npf.EgressAllowedCIDRs, []string{"10.0.0.0/8"}) {
		t.Errorf("EgressAllowedCIDRs = %#v, want [10.0.0.0/8]", npf.EgressAllowedCIDRs)
	}
	if !reflect.DeepEqual(npf.EgressDeniedByExcept, []string{"10.1.2.3/32"}) {
		t.Errorf("EgressDeniedByExcept = %#v, want [10.1.2.3/32]", npf.EgressDeniedByExcept)
	}
}

// TestWorkloadPostureEgressDefaultDeny confirms an Egress-typed NetworkPolicy with
// no egress rules is captured as a raw default-deny structural fact.
func TestWorkloadPostureEgressDefaultDeny(t *testing.T) {
	deploy := deployment("prod", "web", podSpec(container("app", "ghcr.io/acme/web:1")))
	deploy.Spec.Template.Labels = map[string]string{"app": "web"}
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "deny-egress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
	client := fake.NewSimpleClientset(deploy, np)

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	posture := requirePosture(t, inv, "web")
	if posture.NetworkPolicy == nil || !posture.NetworkPolicy.SelectedByEgressPolicy {
		t.Fatalf("expected egress selection, got %#v", posture.NetworkPolicy)
	}
	if !posture.NetworkPolicy.EgressDefaultDeny {
		t.Errorf("EgressDefaultDeny = false, want true")
	}
}

// TestWorkloadPostureAbsentWhenPlain confirms a plain pod template with no notable
// posture emits no posture block (all-omitempty neutral capture).
func TestWorkloadPostureAbsentWhenPlain(t *testing.T) {
	client := fake.NewSimpleClientset(deployment("default", "plain", podSpec(container("app", "ghcr.io/acme/plain:1"))))

	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	for _, r := range inv.Resources {
		if r.Resource.Name == "plain" && r.Posture != nil {
			t.Fatalf("expected no posture for plain workload, got %#v", r.Posture)
		}
	}
}

// posturePodSpec builds a hardened pod template that exercises every podspec-level
// posture field.
func posturePodSpec() corev1.PodSpec {
	readOnly := true
	nonRoot := true
	noEscalate := false
	automount := false
	app := corev1.Container{
		Name:  "app",
		Image: "ghcr.io/acme/api:1.0.0",
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem:   &readOnly,
			RunAsNonRoot:             &nonRoot,
			AllowPrivilegeEscalation: &noEscalate,
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		LivenessProbe:  &corev1.Probe{},
		ReadinessProbe: &corev1.Probe{},
		Env: []corev1.EnvVar{
			{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "api-secret"}, Key: "token",
			}}},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "data", MountPath: "/data"},
			{Name: "config", MountPath: "/config", ReadOnly: true},
		},
	}
	return corev1.PodSpec{
		ServiceAccountName:           "api-sa",
		AutomountServiceAccountToken: &automount,
		Containers:                   []corev1.Container{app},
		Volumes: []corev1.Volume{
			{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}},
		},
		TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
			{TopologyKey: zoneTopologyKey, WhenUnsatisfiable: corev1.DoNotSchedule},
		},
	}
}

func requirePosture(t *testing.T, inv *model.Inventory, name string) *model.WorkloadPosture {
	t.Helper()
	for i := range inv.Resources {
		if inv.Resources[i].Resource.Name == name {
			if inv.Resources[i].Posture == nil {
				t.Fatalf("resource %q has no posture", name)
			}
			return inv.Resources[i].Posture
		}
	}
	t.Fatalf("missing resource %q", name)
	return nil
}
