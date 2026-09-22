package k8s

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestCloudEvidenceFromProviderID(t *testing.T) {
	tests := []struct {
		providerID string
		want       cloudEvidence
	}{
		{"gce://my-proj/us-east4-a/gke-node-1", cloudEvidence{Provider: "gcp", AccountID: "my-proj", Regions: []string{"us-east4"}}},
		{"aws:///us-gov-west-1a/i-0123456789abcdef0", cloudEvidence{Provider: "aws"}},
		{"azure:///subscriptions/0F9A1B2C-3D4E-5F60-7182-93A4B5C6D7E8/resourceGroups/mc_rg/providers/Microsoft.Compute/virtualMachineScaleSets/aks-np/virtualMachines/0", cloudEvidence{Provider: "azure", AccountID: "0f9a1b2c-3d4e-5f60-7182-93a4b5c6d7e8"}},
		{"kind://docker/kind/kind-control-plane", cloudEvidence{}},
		{"", cloudEvidence{}},
	}
	for _, tt := range tests {
		if got := cloudEvidenceFromProviderID(tt.providerID); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("cloudEvidenceFromProviderID(%q) = %#v, want %#v", tt.providerID, got, tt.want)
		}
	}
}

func TestCloudEvidenceFromKubeContext(t *testing.T) {
	tests := []struct {
		kubeContext string
		want        cloudEvidence
	}{
		{"gke_my-proj_us-east4_prod", cloudEvidence{Provider: "gcp", AccountID: "my-proj", Regions: []string{"us-east4"}}},
		{"gke_my-proj_us-central1-c_zonal", cloudEvidence{Provider: "gcp", AccountID: "my-proj", Regions: []string{"us-central1"}}},
		{"arn:aws:eks:us-east-1:123456789012:cluster/prod", cloudEvidence{Provider: "aws", AccountID: "123456789012", Regions: []string{"us-east-1"}}},
		{"arn:aws-us-gov:eks:us-gov-west-1:123456789012:cluster/gov", cloudEvidence{Provider: "aws", AccountID: "123456789012", Regions: []string{"us-gov-west-1"}}},
		{"connectgateway_armory-rally-prod_us-east4_rally-anywhere-prod-cluster", cloudEvidence{Provider: "gcp", AccountID: "armory-rally-prod", Regions: []string{"us-east4"}}},
		// A global fleet membership names no region.
		{"connectgateway_armory-patlytics-prod_global_patlytics-prod-us-east4", cloudEvidence{Provider: "gcp", AccountID: "armory-patlytics-prod"}},
		{"my-aks-cluster", cloudEvidence{}},
		{"", cloudEvidence{}},
	}
	for _, tt := range tests {
		if got := cloudEvidenceFromKubeContext(tt.kubeContext); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("cloudEvidenceFromKubeContext(%q) = %#v, want %#v", tt.kubeContext, got, tt.want)
		}
	}
}

func TestClusterNameFromKubeContext(t *testing.T) {
	tests := map[string]string{
		"gke_my-proj_us-east4_prod":                                 "prod",
		"gke_my-proj_us-central1-c_zonal_with_underscores":          "zonal_with_underscores",
		"arn:aws:eks:us-east-1:123456789012:cluster/prod":           "prod",
		"arn:aws-us-gov:eks:us-gov-west-1:123456789012:cluster/gov": "gov",
		// Real-world contexts: EKS GovCloud, GKE Connect Gateway, and direct GKE.
		"arn:aws-us-gov:eks:us-gov-west-1:280640247078:cluster/scrumptious-mongoose-1743595680": "scrumptious-mongoose-1743595680",
		"arn:aws-us-gov:eks:us-gov-west-1:280640247078:cluster/vdr-eks-managed-eval":            "vdr-eks-managed-eval",
		"connectgateway_armory-athena-staging_global_athena-staging-gke-us-east4":               "athena-staging-gke-us-east4",
		"connectgateway_armory-patlytics-prod_global_patlytics-prod-us-east4":                   "patlytics-prod-us-east4",
		"connectgateway_armory-patlytics-staging_global_patlytics-staging-us-east4":             "patlytics-staging-us-east4",
		"connectgateway_armory-rally-prod_us-east4_rally-anywhere-prod-cluster":                 "rally-anywhere-prod-cluster",
		"connectgateway_armory-rally-staging_us-east4_rally-anywhere-staging-cluster":           "rally-anywhere-staging-cluster",
		"connectgateway_armoryd2v-tcs-dev-prod_us-east4_tcs-prod-cluster":                       "tcs-prod-cluster",
		"gke_armory-patlytics-staging_us-east4_patlytics-staging-us-east4":                      "patlytics-staging-us-east4",
		"gke_armory-rally-prod_us-east4_rally-anywhere-prod-cluster":                            "rally-anywhere-prod-cluster",
		"gke_armory-rally-staging_us-east4_rally-anywhere-staging-cluster":                      "rally-anywhere-staging-cluster",
		"gke_armory-ripcord-staging_us-east4_ripcord-steelix-cluster":                           "ripcord-steelix-cluster",
		"my-aks-cluster": "",
		"kind-kind":      "",
		"":               "",
	}
	for kubeContext, want := range tests {
		if got := clusterNameFromKubeContext(kubeContext); got != want {
			t.Errorf("clusterNameFromKubeContext(%q) = %q, want %q", kubeContext, got, want)
		}
	}
}

func TestCloudEvidenceFromAPIServer(t *testing.T) {
	tests := []struct {
		apiServer string
		want      cloudEvidence
	}{
		{"https://ABCDEF0123456789.gr7.us-east-1.eks.amazonaws.com", cloudEvidence{Provider: "aws", Regions: []string{"us-east-1"}}},
		{"https://abcdef.yl4.us-gov-west-1.eks.amazonaws.com:443", cloudEvidence{Provider: "aws", Regions: []string{"us-gov-west-1"}}},
		{"https://prod-dns-abc123.hcp.eastus.azmk8s.io:443", cloudEvidence{Provider: "azure", Regions: []string{"eastus"}}},
		{"https://gov-abc123.hcp.usgovvirginia.azmk8s.us", cloudEvidence{Provider: "azure", Regions: []string{"usgovvirginia"}}},
		{"https://connectgateway.googleapis.com/v1/projects/123456789012/locations/global/gkeMemberships/patlytics-prod-us-east4", cloudEvidence{Provider: "gcp"}},
		{"https://us-east4-connectgateway.googleapis.com/v1/projects/123456789012/locations/us-east4/gkeMemberships/tcs-prod-cluster", cloudEvidence{Provider: "gcp", Regions: []string{"us-east4"}}},
		{"https://35.1.2.3", cloudEvidence{}},
		{"", cloudEvidence{}},
	}
	for _, tt := range tests {
		if got := cloudEvidenceFromAPIServer(tt.apiServer); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("cloudEvidenceFromAPIServer(%q) = %#v, want %#v", tt.apiServer, got, tt.want)
		}
	}
}

func node(name, providerID string, labels map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{ProviderID: providerID},
	}
}

func TestDetectCloudGKEFromNodes(t *testing.T) {
	client := fake.NewSimpleClientset(
		node("a", "gce://my-proj/us-east4-a/n1", map[string]string{regionTopologyKey: "us-east4"}),
		node("b", "gce://my-proj/us-east4-b/n2", map[string]string{regionTopologyKey: "us-east4"}),
	)
	got, warnings := (&Collector{Client: client, KubeContext: "renamed-context"}).detectCloud(context.Background())
	want := &model.CloudContext{CloudAccount: model.CloudAccount{Provider: "gcp", AccountType: "project", AccountID: "my-proj"}, Regions: []string{"us-east4"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detectCloud = %#v, want %#v", got, want)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
}

func TestDetectCloudEKSAccountComesFromContextARN(t *testing.T) {
	client := fake.NewSimpleClientset(
		node("a", "aws:///us-east-1a/i-1", map[string]string{regionTopologyKey: "us-east-1"}),
	)
	collector := &Collector{
		Client:      client,
		KubeContext: "arn:aws:eks:us-east-1:123456789012:cluster/prod",
		APIServer:   "https://abc.gr7.us-east-1.eks.amazonaws.com",
	}
	got, _ := collector.detectCloud(context.Background())
	want := &model.CloudContext{CloudAccount: model.CloudAccount{Provider: "aws", AccountType: "account", AccountID: "123456789012"}, Regions: []string{"us-east-1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detectCloud = %#v, want %#v", got, want)
	}
}

func TestDetectCloudAKSFromNodesAndHost(t *testing.T) {
	client := fake.NewSimpleClientset(
		node("a", "azure:///subscriptions/0f9a1b2c-3d4e-5f60-7182-93a4b5c6d7e8/resourceGroups/mc/providers/Microsoft.Compute/virtualMachineScaleSets/np/virtualMachines/0", map[string]string{legacyRegionTopologyKey: "eastus"}),
	)
	collector := &Collector{Client: client, KubeContext: "my-aks", APIServer: "https://x.hcp.eastus.azmk8s.io:443"}
	got, _ := collector.detectCloud(context.Background())
	want := &model.CloudContext{CloudAccount: model.CloudAccount{Provider: "azure", AccountType: "subscription", AccountID: "0f9a1b2c-3d4e-5f60-7182-93a4b5c6d7e8"}, Regions: []string{"eastus"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detectCloud = %#v, want %#v", got, want)
	}
}

func TestDetectCloudFallsBackWhenNodeListForbidden(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("nodes is forbidden")
	})
	collector := &Collector{Client: client, KubeContext: "gke_my-proj_us-east4_prod"}
	got, warnings := collector.detectCloud(context.Background())
	want := &model.CloudContext{CloudAccount: model.CloudAccount{Provider: "gcp", AccountType: "project", AccountID: "my-proj"}, Regions: []string{"us-east4"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detectCloud = %#v, want %#v", got, want)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one node-list warning", warnings)
	}
}

func TestDetectCloudConnectGatewayWithoutNodeAccess(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("nodes is forbidden")
	})
	collector := &Collector{
		Client:      client,
		KubeContext: "connectgateway_armoryd2v-tcs-dev-prod_us-east4_tcs-prod-cluster",
		APIServer:   "https://connectgateway.googleapis.com/v1/projects/123456789012/locations/us-east4/gkeMemberships/tcs-prod-cluster",
	}
	got, _ := collector.detectCloud(context.Background())
	want := &model.CloudContext{CloudAccount: model.CloudAccount{Provider: "gcp", AccountType: "project", AccountID: "armoryd2v-tcs-dev-prod"}, Regions: []string{"us-east4"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detectCloud = %#v, want %#v", got, want)
	}
	if name := clusterNameFromKubeContext(collector.KubeContext); name != "tcs-prod-cluster" {
		t.Fatalf("cluster name = %q, want tcs-prod-cluster", name)
	}
}

func TestCollectRecordsCloudScope(t *testing.T) {
	client := fake.NewSimpleClientset(node("a", "gce://my-proj/us-east4-a/n1", nil))
	inv, err := (&Collector{Client: client}).Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	want := &model.CloudContext{CloudAccount: model.CloudAccount{Provider: "gcp", AccountType: "project", AccountID: "my-proj"}, Regions: []string{"us-east4"}}
	if !reflect.DeepEqual(inv.Cloud, want) {
		t.Fatalf("Cloud = %#v, want %#v", inv.Cloud, want)
	}
	if inv.ClusterName != "" {
		t.Fatalf("ClusterName = %q, want empty without a recognizable context", inv.ClusterName)
	}
}

func TestCollectRecordsClusterNameFromKubeContext(t *testing.T) {
	collector := &Collector{Client: fake.NewSimpleClientset(), KubeContext: "gke_my-proj_us-east4_prod"}
	inv, err := collector.Collect(context.Background(), Options{AllNamespaces: true})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if inv.ClusterName != "prod" {
		t.Fatalf("ClusterName = %q, want prod", inv.ClusterName)
	}
}

func TestDetectCloudReturnsNilWithoutEvidence(t *testing.T) {
	client := fake.NewSimpleClientset(node("a", "kind://docker/kind/kind-control-plane", nil))
	got, warnings := (&Collector{Client: client, KubeContext: "kind-kind", APIServer: "https://127.0.0.1:6443"}).detectCloud(context.Background())
	if got != nil {
		t.Fatalf("detectCloud = %#v, want nil", got)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
}
