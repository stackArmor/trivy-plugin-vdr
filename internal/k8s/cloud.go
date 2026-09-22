package k8s

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Well-known node labels carrying the cloud region.
const (
	regionTopologyKey       = "topology.kubernetes.io/region"
	legacyRegionTopologyKey = "failure-domain.beta.kubernetes.io/region"
)

var (
	// gke_<project>_<location>_<cluster> (direct control-plane access) or
	// connectgateway_<project>_<location>_<membership> (fleet Connect Gateway,
	// where location is often "global"); project IDs never contain "_".
	gkeContextPattern = regexp.MustCompile(`^(?:gke|connectgateway)_([^_]+)_([^_]+)_(.+)$`)
	// connectgateway.googleapis.com, or <region>-connectgateway.googleapis.com
	// for regional fleet memberships.
	connectGatewayHostPattern = regexp.MustCompile(`^(?:([a-z]+-[a-z]+\d+)-)?connectgateway\.googleapis\.com$`)
	// arn:<partition>:eks:<region>:<account>:cluster/<name>
	eksContextPattern = regexp.MustCompile(`^arn:[a-z0-9-]+:eks:([a-z0-9-]+):(\d{12}):cluster/(.+)$`)
	// <id>.<hash>.<region>.eks.amazonaws.com (also .amazonaws.com.cn)
	eksHostPattern = regexp.MustCompile(`\.([a-z]{2}(?:-[a-z]+)+-\d)\.eks\.amazonaws\.com(?:\.cn)?$`)
	// <name>.hcp.<region>.azmk8s.io / .azmk8s.us / .azmk8s.cn, or
	// <name>.<region>.azmk8s.io (older private clusters).
	aksHostPattern = regexp.MustCompile(`\.(?:hcp\.)?([a-z0-9]+)\.azmk8s\.(?:io|us|cn)$`)
	// azure:///subscriptions/<sub>/resourceGroups/...
	azureProviderIDPattern = regexp.MustCompile(`^azure:///subscriptions/([0-9a-fA-F-]{36})/`)
	// GCE/GKE zones are <region>-<letter>, e.g. us-east4-a.
	gceZoneSuffixPattern = regexp.MustCompile(`-[a-z]$`)
)

// cloudEvidence is one partial observation of the cloud scope. Fields are
// merged by DetectCloud with earlier evidence winning per field.
type cloudEvidence struct {
	Provider  string
	AccountID string
	Regions   []string
}

// detectCloud identifies the cloud provider, account/project/subscription, and
// region(s) of the cluster the collector points at. It merges, in priority
// order, node providerIDs and topology labels, the kubeconfig context name, and
// the API server host. It never fails: unknown fields are left empty, a nil
// result means no cloud evidence was found at all, and problems (such as RBAC
// forbidding a node list) are returned as warnings.
func (c *Collector) detectCloud(ctx context.Context) (*model.CloudContext, []string) {
	var warnings []string
	var evidence []cloudEvidence
	nodes, err := c.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("cloud detection: could not list nodes (%v); falling back to the kube context and API server host", err))
	} else {
		for _, node := range nodes.Items {
			evidence = append(evidence, cloudEvidenceFromNode(node))
		}
	}
	evidence = append(evidence, cloudEvidenceFromKubeContext(c.KubeContext), cloudEvidenceFromAPIServer(c.APIServer))
	return mergeCloudEvidence(evidence), warnings
}

// mergeCloudEvidence folds partial observations into one CloudContext. The
// first non-empty provider and account win; regions are unioned. Evidence that
// names a different provider than the winner is ignored so a mislabelled hint
// cannot mix scopes.
func mergeCloudEvidence(evidence []cloudEvidence) *model.CloudContext {
	var provider, accountID string
	for _, ev := range evidence {
		if ev.Provider != "" {
			provider = ev.Provider
			break
		}
	}
	var regions []string
	for _, ev := range evidence {
		if ev.Provider != "" && ev.Provider != provider {
			continue
		}
		if accountID == "" {
			accountID = ev.AccountID
		}
		regions = append(regions, ev.Regions...)
	}
	return model.NewCloudContext(provider, accountID, regions)
}

// cloudEvidenceFromNode combines a node's providerID with its region topology
// label.
func cloudEvidenceFromNode(node corev1.Node) cloudEvidence {
	ev := cloudEvidenceFromProviderID(node.Spec.ProviderID)
	for _, key := range []string{regionTopologyKey, legacyRegionTopologyKey} {
		if region := node.Labels[key]; region != "" {
			ev.Regions = append(ev.Regions, region)
			break
		}
	}
	return ev
}

// cloudEvidenceFromProviderID parses a node's spec.providerID:
//
//	gce://<project>/<zone>/<instance>
//	aws:///<zone>/<instance-id>
//	azure:///subscriptions/<sub>/resourceGroups/<rg>/providers/...
func cloudEvidenceFromProviderID(providerID string) cloudEvidence {
	providerID = strings.TrimSpace(providerID)
	switch {
	case strings.HasPrefix(providerID, "gce://"):
		ev := cloudEvidence{Provider: model.CloudProviderGCP}
		rest := strings.TrimPrefix(providerID, "gce://")
		parts := strings.Split(rest, "/")
		if len(parts) >= 1 && parts[0] != "" {
			ev.AccountID = parts[0]
		}
		if len(parts) >= 2 {
			if region := gceZoneToRegion(parts[1]); region != "" {
				ev.Regions = append(ev.Regions, region)
			}
		}
		return ev
	case strings.HasPrefix(providerID, "aws://"):
		return cloudEvidence{Provider: model.CloudProviderAWS}
	case strings.HasPrefix(providerID, "azure://"):
		ev := cloudEvidence{Provider: model.CloudProviderAzure}
		if m := azureProviderIDPattern.FindStringSubmatch(providerID); m != nil {
			ev.AccountID = strings.ToLower(m[1])
		}
		return ev
	}
	return cloudEvidence{}
}

// cloudEvidenceFromKubeContext parses the conventional context names written by
// `gcloud container clusters get-credentials` (with or without
// `--connect-gateway`, or `gcloud container fleet memberships get-credentials`)
// and `aws eks update-kubeconfig`.
func cloudEvidenceFromKubeContext(kubeContext string) cloudEvidence {
	kubeContext = strings.TrimSpace(kubeContext)
	if m := gkeContextPattern.FindStringSubmatch(kubeContext); m != nil {
		ev := cloudEvidence{Provider: model.CloudProviderGCP, AccountID: m[1]}
		if region := gceZoneToRegion(m[2]); region != "" && region != "global" {
			ev.Regions = []string{region}
		}
		return ev
	}
	if m := eksContextPattern.FindStringSubmatch(kubeContext); m != nil {
		return cloudEvidence{Provider: model.CloudProviderAWS, AccountID: m[2], Regions: []string{m[1]}}
	}
	return cloudEvidence{}
}

// clusterNameFromKubeContext extracts the cluster (or, for Connect Gateway,
// fleet membership) name from the same conventional GKE and EKS context names. Other contexts (AKS, kind, renamed
// contexts) carry no recognizable cluster name and yield "".
func clusterNameFromKubeContext(kubeContext string) string {
	kubeContext = strings.TrimSpace(kubeContext)
	if m := gkeContextPattern.FindStringSubmatch(kubeContext); m != nil {
		return m[3]
	}
	if m := eksContextPattern.FindStringSubmatch(kubeContext); m != nil {
		return m[3]
	}
	return ""
}

// cloudEvidenceFromAPIServer parses the managed-control-plane hostnames used by
// EKS, AKS, and GKE Connect Gateway. Direct GKE endpoints are bare IPs and
// carry no evidence. The Connect Gateway URL path names the project by number,
// not ID, so it is not used as the account.
func cloudEvidenceFromAPIServer(apiServer string) cloudEvidence {
	host := strings.ToLower(apiServerHost(apiServer))
	if host == "" {
		return cloudEvidence{}
	}
	if m := connectGatewayHostPattern.FindStringSubmatch(host); m != nil {
		ev := cloudEvidence{Provider: model.CloudProviderGCP}
		if m[1] != "" {
			ev.Regions = []string{m[1]}
		}
		return ev
	}
	if m := eksHostPattern.FindStringSubmatch(host); m != nil {
		return cloudEvidence{Provider: model.CloudProviderAWS, Regions: []string{m[1]}}
	}
	if m := aksHostPattern.FindStringSubmatch(host); m != nil {
		return cloudEvidence{Provider: model.CloudProviderAzure, Regions: []string{m[1]}}
	}
	return cloudEvidence{}
}

// gceZoneToRegion reduces a GCE zone (us-east4-a) to its region (us-east4).
// A value that is already a region is returned unchanged.
func gceZoneToRegion(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	return gceZoneSuffixPattern.ReplaceAllString(location, "")
}
