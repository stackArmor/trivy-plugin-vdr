package k8s

import (
	"context"
	"sort"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// zoneTopologyKey is the well-known label carrying an availability zone; used to
// observe (not interpret) whether a pod template requires cross-zone spread.
const zoneTopologyKey = "topology.kubernetes.io/zone"

// workloadPosture derives the read-only, neutral security-posture facts
// observable from a pod template. Cluster-object facts (NetworkPolicy selection,
// PodDisruptionBudget) are added later by the namespace collectors. Returns nil
// when the template yields no facts worth emitting.
func workloadPosture(spec corev1.PodSpec, replicas *int32) *model.WorkloadPosture {
	p := &model.WorkloadPosture{
		SecurityContext: postureSecurityContext(spec),
		Workload:        postureWorkload(spec, replicas),
		Identity:        postureIdentity(spec),
		Volumes:         postureVolumes(spec),
	}
	if p.SecurityContext == nil && p.Workload == nil && p.Identity == nil && p.Volumes == nil {
		return nil
	}
	return p
}

func postureSecurityContext(spec corev1.PodSpec) *model.PostureSecurityContext {
	sc := &model.PostureSecurityContext{}
	if len(spec.Containers) > 0 {
		allReadOnly := true
		allNonRoot := true
		for _, c := range spec.Containers {
			cs := c.SecurityContext
			if cs == nil || cs.ReadOnlyRootFilesystem == nil || !*cs.ReadOnlyRootFilesystem {
				allReadOnly = false
			}
			if !containerRunAsNonRoot(spec, c) {
				allNonRoot = false
			}
			if cs != nil && cs.Privileged != nil && *cs.Privileged {
				sc.Privileged = true
			}
			if cs != nil && cs.AllowPrivilegeEscalation != nil && *cs.AllowPrivilegeEscalation {
				sc.AllowPrivilegeEscalation = true
			}
		}
		sc.ReadOnlyRootFilesystem = allReadOnly
		sc.RunAsNonRoot = allNonRoot
	}
	sc.DroppedCapabilities = commonDroppedCapabilities(spec.Containers)
	sc.SeccompProfileType = seccompProfileType(spec)

	if !sc.ReadOnlyRootFilesystem && !sc.RunAsNonRoot && !sc.Privileged &&
		!sc.AllowPrivilegeEscalation && len(sc.DroppedCapabilities) == 0 && sc.SeccompProfileType == "" {
		return nil
	}
	return sc
}

// containerRunAsNonRoot reports whether a container effectively runs as non-root:
// its own securityContext.runAsNonRoot when set, otherwise the pod-level value.
func containerRunAsNonRoot(spec corev1.PodSpec, c corev1.Container) bool {
	if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
		return *c.SecurityContext.RunAsNonRoot
	}
	if spec.SecurityContext != nil && spec.SecurityContext.RunAsNonRoot != nil {
		return *spec.SecurityContext.RunAsNonRoot
	}
	return false
}

// commonDroppedCapabilities returns the capabilities dropped by every app
// container (the intersection of each container's capabilities.drop), sorted.
func commonDroppedCapabilities(containers []corev1.Container) []string {
	if len(containers) == 0 {
		return nil
	}
	var common map[string]int
	for _, c := range containers {
		dropped := map[string]struct{}{}
		if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
			for _, cap := range c.SecurityContext.Capabilities.Drop {
				dropped[string(cap)] = struct{}{}
			}
		}
		if common == nil {
			common = map[string]int{}
			for name := range dropped {
				common[name] = 1
			}
			continue
		}
		for name := range common {
			if _, ok := dropped[name]; ok {
				common[name]++
			}
		}
	}
	out := make([]string, 0, len(common))
	for name, count := range common {
		if count == len(containers) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// seccompProfileType returns the seccompProfile.type in effect: the pod-level
// value, else the type shared by all app containers (empty when they disagree or
// none is set).
func seccompProfileType(spec corev1.PodSpec) string {
	if spec.SecurityContext != nil && spec.SecurityContext.SeccompProfile != nil {
		return string(spec.SecurityContext.SeccompProfile.Type)
	}
	if len(spec.Containers) == 0 {
		return ""
	}
	shared := ""
	for i, c := range spec.Containers {
		t := ""
		if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
			t = string(c.SecurityContext.SeccompProfile.Type)
		}
		if i == 0 {
			shared = t
			continue
		}
		if t != shared {
			return ""
		}
	}
	return shared
}

func postureWorkload(spec corev1.PodSpec, replicas *int32) *model.PostureWorkload {
	w := &model.PostureWorkload{}
	if replicas != nil {
		v := *replicas
		w.Replicas = &v
	}
	w.ZoneSpread = hasZoneSpread(spec)
	for _, c := range spec.Containers {
		if c.LivenessProbe != nil {
			w.LivenessProbe = true
		}
		if c.ReadinessProbe != nil {
			w.ReadinessProbe = true
		}
	}
	if w.Replicas == nil && !w.ZoneSpread && !w.LivenessProbe && !w.ReadinessProbe {
		return nil
	}
	return w
}

// hasZoneSpread reports whether the pod template requires cross-zone placement: a
// topologySpreadConstraint on the zone key with whenUnsatisfiable=DoNotSchedule,
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

func postureIdentity(spec corev1.PodSpec) *model.PostureIdentity {
	id := &model.PostureIdentity{ServiceAccountName: spec.ServiceAccountName}
	if spec.AutomountServiceAccountToken != nil {
		v := *spec.AutomountServiceAccountToken
		id.AutomountServiceAccountToken = &v
	}
	containers := append(append([]corev1.Container(nil), spec.Containers...), spec.InitContainers...)
	for _, c := range containers {
		if containerHasSecretEnv(c) {
			id.EnvFromSecretRef = true
		}
	}
	if id.ServiceAccountName == "" && id.AutomountServiceAccountToken == nil && !id.EnvFromSecretRef {
		return nil
	}
	return id
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

func postureVolumes(spec corev1.PodSpec) *model.PostureVolumes {
	writable := writableVolumeNames(spec)
	if len(writable) == 0 {
		return nil
	}
	paths := map[string]struct{}{}
	containers := append(append([]corev1.Container(nil), spec.Containers...), spec.InitContainers...)
	for _, c := range containers {
		for _, m := range c.VolumeMounts {
			if writable[m.Name] && !m.ReadOnly {
				paths[m.MountPath] = struct{}{}
			}
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return &model.PostureVolumes{WritableVolumeMounts: sortedSet(paths)}
}

// writableVolumeNames returns the set of pod volume names backed by writable
// storage (emptyDir, PVC, generic ephemeral, or hostPath).
func writableVolumeNames(spec corev1.PodSpec) map[string]bool {
	out := map[string]bool{}
	for _, v := range spec.Volumes {
		if v.EmptyDir != nil || v.PersistentVolumeClaim != nil || v.Ephemeral != nil || v.HostPath != nil {
			out[v.Name] = true
		}
	}
	return out
}

// collectNetworkPolicyPosture reads NetworkPolicies in the namespace and records
// the raw egress/ingress selection facts on the workloads each policy selects.
// Best-effort and fail-open: an RBAC/API error leaves the fields unset.
func (c *Collector) collectNetworkPolicyPosture(ctx context.Context, namespace string, builder *inventoryBuilder) {
	list, err := c.Client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		np := &list.Items[i]
		hasEgress := policyTypesInclude(np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)
		hasIngress := policyTypesInclude(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
		// When policyTypes is omitted the API implies Ingress, and Egress only when
		// egress rules are present. Capture that structural fact verbatim.
		if len(np.Spec.PolicyTypes) == 0 {
			hasIngress = true
			hasEgress = len(np.Spec.Egress) > 0
		}
		if !hasEgress && !hasIngress {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			continue
		}

		var allowedCIDRs, deniedByExcept []string
		egressDefaultDeny := false
		if hasEgress {
			egressDefaultDeny = len(np.Spec.Egress) == 0
			for _, rule := range np.Spec.Egress {
				for _, to := range rule.To {
					if to.IPBlock == nil {
						continue
					}
					if to.IPBlock.CIDR != "" {
						allowedCIDRs = append(allowedCIDRs, to.IPBlock.CIDR)
					}
					deniedByExcept = append(deniedByExcept, to.IPBlock.Except...)
				}
			}
		}

		for j := range builder.inventory.Resources {
			r := &builder.inventory.Resources[j]
			if r.Resource.Namespace != np.Namespace {
				continue
			}
			if !selector.Matches(labels.Set(r.Labels)) {
				continue
			}
			npf := ensureNetworkPolicy(ensurePosture(r))
			if hasEgress {
				npf.SelectedByEgressPolicy = true
				if egressDefaultDeny {
					npf.EgressDefaultDeny = true
				}
				npf.EgressAllowedCIDRs = mergeSorted(npf.EgressAllowedCIDRs, allowedCIDRs)
				npf.EgressDeniedByExcept = mergeSorted(npf.EgressDeniedByExcept, deniedByExcept)
			}
			if hasIngress {
				npf.SelectedByIngressPolicy = true
			}
		}
	}
}

// collectPodDisruptionBudgetPosture reads PodDisruptionBudgets in the namespace
// and marks HasPodDisruptionBudget on the workloads each PDB selects. Best-effort
// and fail-open.
func (c *Collector) collectPodDisruptionBudgetPosture(ctx context.Context, namespace string, builder *inventoryBuilder) {
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
		for j := range builder.inventory.Resources {
			r := &builder.inventory.Resources[j]
			if r.Resource.Namespace != pdb.Namespace {
				continue
			}
			if selector.Empty() || !selector.Matches(labels.Set(r.Labels)) {
				continue
			}
			ensureWorkload(ensurePosture(r)).HasPodDisruptionBudget = true
		}
	}
}

func policyTypesInclude(types []networkingv1.PolicyType, want networkingv1.PolicyType) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

func ensurePosture(r *model.ResourceInventory) *model.WorkloadPosture {
	if r.Posture == nil {
		r.Posture = &model.WorkloadPosture{}
	}
	return r.Posture
}

func ensureWorkload(p *model.WorkloadPosture) *model.PostureWorkload {
	if p.Workload == nil {
		p.Workload = &model.PostureWorkload{}
	}
	return p.Workload
}

func ensureNetworkPolicy(p *model.WorkloadPosture) *model.PostureNetworkPolicy {
	if p.NetworkPolicy == nil {
		p.NetworkPolicy = &model.PostureNetworkPolicy{}
	}
	return p.NetworkPolicy
}

// mergeSorted unions two string slices into a sorted, de-duplicated slice.
func mergeSorted(existing, added []string) []string {
	if len(existing) == 0 && len(added) == 0 {
		return existing
	}
	set := map[string]struct{}{}
	for _, v := range existing {
		set[v] = struct{}{}
	}
	for _, v := range added {
		set[v] = struct{}{}
	}
	return sortedSet(set)
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
