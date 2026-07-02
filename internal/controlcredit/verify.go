package controlcredit

import (
	"fmt"
	"sort"
	"strings"
)

// Platform labels the verification-source key used to select a control's
// predicate for an asset. This milestone (CC2) implements k8s-native collectors
// only; other platforms verify nothing until their collectors land.
const (
	PlatformKubernetes = "kubernetes"
	PlatformVMSystemd  = "vm-systemd"
	PlatformAWSManaged = "aws-managed"
	PlatformGCPManaged = "gcp-managed"
)

// tokenTTLMaxSeconds is the projected service-account-token expiry ceiling the
// no-env-secrets-short-lived-identity control requires (verification-sources.yaml
// "TTL<=1h").
const tokenTTLMaxSeconds = 3600

// haMinReplicas is the replica floor the verified-ha control requires
// (verification-sources.yaml "replicas>=3").
const haMinReplicas = 3

// AssetFacts are the machine-observable properties of one asset that the
// verification collectors evaluate. The caller (report wiring) populates it from
// internal/k8s + internal/exposure. Every field is fail-closed: an unset/false
// value means "not observed", so a control that depends on it verifies as
// not-verified rather than being assumed present.
type AssetFacts struct {
	Platform string

	// Pod-spec-derived (k8s).
	ReadOnlyRootFS           bool  // every non-init container readOnlyRootFilesystem=true
	WritableAppVolume        bool  // a writable emptyDir/PVC/tmpfs is mounted rw
	EnvSecret                bool  // any container sources env from a Secret
	ProjectedTokenTTLSeconds int64 // smallest projected token expiry (0 = none)
	ShortLivedIdentity       bool  // IRSA/GKE Workload Identity annotation present
	Replicas                 int   // desired replicas; <0 = not applicable/unknown
	HasLivenessProbe         bool
	ZoneSpread               bool // topology spread / required zone anti-affinity
	HasPodDisruptionBudget   bool

	// Cluster-object-derived (k8s).
	EgressDefaultDeny bool // NetworkPolicy egress default-deny selects the workload
	ImdsBlocked       bool // NetworkPolicy denies egress to 169.254.169.254/32

	// Exposure (internal/exposure).
	InternetReachable bool
}

// VerificationResult records the outcome of evaluating one control's predicate
// against an asset, for both the join engine and near-miss reporting.
type VerificationResult struct {
	Control string
	// Applicable is true when a verification-source predicate exists for the
	// asset's platform. A row whose control is inapplicable here fires nowhere.
	Applicable bool
	Verified   bool
	// Evidence is a short proof string when verified.
	Evidence string
	// FailedPredicate names the specific check that failed (near-miss reporting)
	// or why the control is inapplicable/uncollected on this platform.
	FailedPredicate string
}

// VerifyControls evaluates every control referenced by the taxonomy against the
// asset and returns the per-control verification records. A disabled taxonomy
// returns an empty map (the credit engine is inert).
func (t *Taxonomy) VerifyControls(a AssetFacts) map[string]VerificationResult {
	out := map[string]VerificationResult{}
	if t == nil || !t.Enabled {
		return out
	}
	for _, name := range t.referencedControls() {
		out[name] = t.verifyControl(name, a)
	}
	return out
}

// referencedControls returns the sorted set of control names any row depends on.
func (t *Taxonomy) referencedControls() []string {
	seen := map[string]bool{}
	for _, r := range t.Rows {
		if name := strings.TrimSpace(r.Control.Name); name != "" {
			seen[name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// verifyControl proves a single control on the asset's platform. A control with
// no predicate for the platform is inapplicable (cleanly not verified). A control
// whose k8s collector this milestone does not implement is not verified with a
// TODO failed-predicate, never assumed present.
func (t *Taxonomy) verifyControl(name string, a AssetFacts) VerificationResult {
	res := VerificationResult{Control: name}
	src, ok := t.VerificationSources[name]
	predicate := ""
	if ok {
		predicate = strings.TrimSpace(src[a.Platform])
	}
	if predicate == "" {
		res.FailedPredicate = fmt.Sprintf("no %s verification source for control %q", a.Platform, name)
		return res
	}
	res.Applicable = true

	if a.Platform != PlatformKubernetes {
		res.FailedPredicate = fmt.Sprintf("%s collector for %q not implemented (CC2 is k8s-native only)", a.Platform, name)
		return res
	}

	verified, evidence, failed, implemented := evalK8sControl(name, a)
	if !implemented {
		res.FailedPredicate = fmt.Sprintf("k8s collector for %q not implemented in CC2: %s", name, firstLine(predicate))
		return res
	}
	res.Verified = verified
	res.Evidence = evidence
	res.FailedPredicate = failed
	return res
}

// evalK8sControl runs the k8s-native collector for a control. implemented=false
// marks controls whose k8s signal this milestone does not collect (ingress
// rate-limit/body-size/CSP, mesh CRDs, image-layer shell detection); those never
// verify and are reported as near-misses with a TODO. Cloud-managed and
// STIG-file controls have no kubernetes predicate and never reach here.
func evalK8sControl(name string, a AssetFacts) (verified bool, evidence, failedPredicate string, implemented bool) {
	switch name {
	case "readonly-rootfs":
		if !a.ReadOnlyRootFS {
			return false, "", "not every container sets securityContext.readOnlyRootFilesystem=true", true
		}
		if a.WritableAppVolume {
			return false, "", "a writable volume (emptyDir/PVC/tmpfs) is mounted read-write into a container", true
		}
		return true, "every container readOnlyRootFilesystem=true; no writable app volume mounted", "", true

	case "no-env-secrets-short-lived-identity":
		if a.EnvSecret {
			return false, "", "a container sources an environment variable from a Secret (env.valueFrom.secretKeyRef/envFrom.secretRef)", true
		}
		if a.ProjectedTokenTTLSeconds <= 0 || a.ProjectedTokenTTLSeconds > tokenTTLMaxSeconds {
			return false, "", fmt.Sprintf("no projected service-account token with expirationSeconds<=%d observed", tokenTTLMaxSeconds), true
		}
		ev := fmt.Sprintf("no Secret-sourced env vars; projected token TTL %ds (<=%ds)", a.ProjectedTokenTTLSeconds, tokenTTLMaxSeconds)
		if a.ShortLivedIdentity {
			ev += "; cloud short-lived identity annotation present"
		}
		return true, ev, "", true

	case "egress-default-deny":
		if !a.EgressDefaultDeny {
			return false, "", "no Egress-policyType NetworkPolicy with a default-deny posture selects the workload", true
		}
		return true, "Egress default-deny NetworkPolicy selects the workload; allow-list carries no 0.0.0.0/0", "", true

	case "imds-protection":
		if !a.ImdsBlocked {
			return false, "", "no NetworkPolicy denies egress to 169.254.169.254/32", true
		}
		return true, "NetworkPolicy denies workload egress to 169.254.169.254/32", "", true

	case "verified-ha":
		var missing []string
		if a.Replicas < haMinReplicas {
			missing = append(missing, fmt.Sprintf("replicas=%d (<%d)", a.Replicas, haMinReplicas))
		}
		if !a.ZoneSpread {
			missing = append(missing, "no zone topologySpread/anti-affinity")
		}
		if !a.HasPodDisruptionBudget {
			missing = append(missing, "no PodDisruptionBudget")
		}
		if !a.HasLivenessProbe {
			missing = append(missing, "no liveness probe")
		}
		if len(missing) > 0 {
			return false, "", "missing " + strings.Join(missing, ", "), true
		}
		return true, fmt.Sprintf("replicas>=%d, zone spread, PodDisruptionBudget, liveness probe", haMinReplicas), "", true

	default:
		// Controls whose k8s signal this milestone does not collect: no-shell-image
		// (image-layer inspection), route-rate-limit/request-size-limit/strict-csp/
		// session-cookie-flags/samesite-session-cookies/desync-mitigation (ingress
		// config), mesh-strict-mtls/mesh-request-authn (Istio CRDs),
		// exec-restricted-writable-paths/selinux-confinement/application-allowlisting
		// (node/STIG signals). They never verify; a later milestone lands them.
		return false, "", "", false
	}
}

// firstLine trims a predicate to its first line for compact near-miss messages.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
