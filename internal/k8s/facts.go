package k8s

import (
	"context"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// imdsCIDR is the link-local instance-metadata-service address the
// imds-protection control requires be denied on egress.
const imdsCIDR = "169.254.169.254/32"

// zoneTopologyKey is the well-known label carrying an availability zone, used to
// detect cross-zone spread for the verified-ha control.
const zoneTopologyKey = "topology.kubernetes.io/zone"

// podSpecFacts derives the control-credit verification facts observable from a
// pod template: read-only rootfs, writable app volumes, Secret-sourced env,
// projected token TTL, short-lived cloud identity, liveness probes, and zone
// spread. Cluster-object facts (egress default-deny, IMDS block, PDB) are added
// later by the NetworkPolicy/PDB collectors.
func podSpecFacts(spec corev1.PodSpec, annotations map[string]string, replicas *int32) *model.WorkloadFacts {
	facts := &model.WorkloadFacts{}
	if replicas != nil {
		v := *replicas
		facts.Replicas = &v
	}
	facts.ZoneSpread = hasZoneSpread(spec)
	facts.ProjectedTokenTTLSeconds = minProjectedTokenTTL(spec)
	facts.ShortLivedIdentity = hasShortLivedIdentity(annotations)

	writableVolumes := writableVolumeNames(spec)

	containers := append(append([]corev1.Container(nil), spec.Containers...), spec.InitContainers...)
	allReadOnly := len(spec.Containers) > 0
	for _, c := range spec.Containers {
		if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			allReadOnly = false
		}
		if c.LivenessProbe != nil {
			facts.HasLivenessProbe = true
		}
	}
	facts.AllReadOnlyRootFS = allReadOnly

	for _, c := range containers {
		if containerHasSecretEnv(c) {
			facts.EnvSecret = true
		}
		if containerMountsWritable(c, writableVolumes) {
			facts.WritableAppVolume = true
		}
	}
	return facts
}

// hasZoneSpread reports whether the pod template requires cross-zone placement:
// a topologySpreadConstraint on the zone key with whenUnsatisfiable=DoNotSchedule,
// or a required zone anti-affinity term.
func hasZoneSpread(spec corev1.PodSpec) bool {
	for _, tsc := range spec.TopologySpreadConstraints {
		if tsc.TopologyKey == zoneTopologyKey && tsc.WhenUnsatisfiable == corev1.DoNotSchedule {
			return true
		}
	}
	if spec.Affinity != nil && spec.Affinity.PodAntiAffinity != nil {
		for _, term := range spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
			if term.TopologyKey == zoneTopologyKey {
				return true
			}
		}
	}
	return false
}

// minProjectedTokenTTL returns the smallest projected service-account-token
// expirationSeconds across the pod's volumes (0 when none is projected).
func minProjectedTokenTTL(spec corev1.PodSpec) int64 {
	var min int64
	for _, v := range spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, src := range v.Projected.Sources {
			if src.ServiceAccountToken == nil || src.ServiceAccountToken.ExpirationSeconds == nil {
				continue
			}
			ttl := *src.ServiceAccountToken.ExpirationSeconds
			if ttl > 0 && (min == 0 || ttl < min) {
				min = ttl
			}
		}
	}
	return min
}

// hasShortLivedIdentity reports whether an IRSA or GKE Workload Identity
// annotation is present (best-effort; the authoritative annotation lives on the
// ServiceAccount object, not collected in this milestone).
func hasShortLivedIdentity(annotations map[string]string) bool {
	if annotations == nil {
		return false
	}
	if _, ok := annotations["eks.amazonaws.com/role-arn"]; ok {
		return true
	}
	if _, ok := annotations["iam.gke.io/gcp-service-account"]; ok {
		return true
	}
	return false
}

// writableVolumeNames returns the set of pod volume names that are writable
// (emptyDir, PVC, or generic ephemeral); a read-only mount of one still counts as
// writable storage the workload can be pointed at.
func writableVolumeNames(spec corev1.PodSpec) map[string]bool {
	out := map[string]bool{}
	for _, v := range spec.Volumes {
		if v.EmptyDir != nil || v.PersistentVolumeClaim != nil || v.Ephemeral != nil {
			out[v.Name] = true
		}
	}
	return out
}

// containerMountsWritable reports whether a container mounts one of the writable
// volumes read-write.
func containerMountsWritable(c corev1.Container, writable map[string]bool) bool {
	for _, m := range c.VolumeMounts {
		if writable[m.Name] && !m.ReadOnly {
			return true
		}
	}
	return false
}

// containerHasSecretEnv reports whether a container sources any env var from a
// Secret (env.valueFrom.secretKeyRef or envFrom.secretRef).
func containerHasSecretEnv(c corev1.Container) bool {
	for _, e := range c.Env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			return true
		}
	}
	for _, e := range c.EnvFrom {
		if e.SecretRef != nil {
			return true
		}
	}
	return false
}

// collectNetworkPolicyFacts reads NetworkPolicies in the namespace and marks
// EgressDefaultDeny / ImdsBlocked on the workloads each policy selects.
// Best-effort: RBAC or API failures leave the facts unset (fail-closed).
func (c *Collector) collectNetworkPolicyFacts(ctx context.Context, namespace string, builder *inventoryBuilder) {
	list, err := c.Client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		np := &list.Items[i]
		egress := policyTypesInclude(np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
		if !egress {
			continue
		}
		defaultDeny := egressDefaultDeny(np)
		imdsBlocked := egressBlocksIMDS(np)
		if !defaultDeny && !imdsBlocked {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			continue
		}
		for j := range builder.inventory.Resources {
			r := &builder.inventory.Resources[j]
			if r.Resource.Namespace != np.Namespace || r.Facts == nil {
				continue
			}
			if !selector.Matches(labels.Set(r.Labels)) {
				continue
			}
			if defaultDeny {
				r.Facts.EgressDefaultDeny = true
			}
			if imdsBlocked {
				r.Facts.ImdsBlocked = true
			}
		}
	}
}

// egressDefaultDeny reports whether an Egress NetworkPolicy is a default-deny
// posture: either no egress rules at all (deny all), or every rule's allow-list
// destinations exclude the 0.0.0.0/0 wildcard.
func egressDefaultDeny(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.Egress) == 0 {
		return true // selecting an Egress policy with no rules denies all egress
	}
	for _, rule := range np.Spec.Egress {
		for _, to := range rule.To {
			if to.IPBlock != nil && to.IPBlock.CIDR == "0.0.0.0/0" && len(to.IPBlock.Except) == 0 {
				return false // an uncontrolled internet allow-list defeats default-deny
			}
		}
	}
	return true
}

// egressBlocksIMDS reports whether the policy is default-deny egress (no rule
// permits the link-local metadata address). A default-deny egress policy that
// does not carve out 169.254.169.254 blocks IMDS.
func egressBlocksIMDS(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.Egress) == 0 {
		return true
	}
	for _, rule := range np.Spec.Egress {
		for _, to := range rule.To {
			if to.IPBlock == nil {
				continue
			}
			// An allow-list containing the whole internet (and not excepting IMDS)
			// leaves the metadata service reachable.
			if to.IPBlock.CIDR == "0.0.0.0/0" && !exceptsIMDS(to.IPBlock.Except) {
				return false
			}
		}
	}
	return true
}

func exceptsIMDS(except []string) bool {
	for _, e := range except {
		if e == imdsCIDR || e == "169.254.169.254/32" || e == "169.254.0.0/16" {
			return true
		}
	}
	return false
}

func policyTypesInclude(types []networkingv1.PolicyType, want networkingv1.PolicyType) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

// collectPodDisruptionBudgetFacts reads PodDisruptionBudgets in the namespace and
// marks HasPodDisruptionBudget on the workloads each PDB selects. Best-effort.
func (c *Collector) collectPodDisruptionBudgetFacts(ctx context.Context, namespace string, builder *inventoryBuilder) {
	list, err := c.Client.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		pdb := &list.Items[i]
		if pdb.Spec.Selector == nil {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		markSelected(builder, pdb.Namespace, selector, func(f *model.WorkloadFacts) { f.HasPodDisruptionBudget = true })
	}
}

func markSelected(builder *inventoryBuilder, namespace string, selector labels.Selector, set func(*model.WorkloadFacts)) {
	for j := range builder.inventory.Resources {
		r := &builder.inventory.Resources[j]
		if r.Resource.Namespace != namespace || r.Facts == nil {
			continue
		}
		if selector.Empty() || !selector.Matches(labels.Set(r.Labels)) {
			continue
		}
		set(r.Facts)
	}
}
