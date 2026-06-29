package cloudrun

import (
	"testing"

	"cloud.google.com/go/compute/apiv1/computepb"
)

func TestServerlessNEGParsesCloudRunService(t *testing.T) {
	neg := &computepb.NetworkEndpointGroup{
		Name:                ptrString("api-neg"),
		Region:              ptrString("https://www.googleapis.com/compute/v1/projects/proj/regions/us-east4"),
		NetworkEndpointType: ptrString("SERVERLESS"),
		CloudRun:            &computepb.NetworkEndpointGroupCloudRun{Service: ptrString("api")},
	}

	service, region, ok := cloudRunServiceFromNEG(neg)
	if !ok {
		t.Fatal("cloudRunServiceFromNEG ok = false, want true")
	}
	if service != "api" {
		t.Fatalf("service = %q, want api", service)
	}
	if region != "us-east4" {
		t.Fatalf("region = %q, want us-east4", region)
	}
}

func TestExternalSchemeClassifiesPublicForwardingRules(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "EXTERNAL", want: true},
		{name: "EXTERNAL_MANAGED", want: true},
		{name: "INTERNAL_MANAGED", want: false},
		{name: "INTERNAL", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPublicLoadBalancingScheme(tt.name); got != tt.want {
				t.Fatalf("isPublicLoadBalancingScheme(%q) = %t, want %t", tt.name, got, tt.want)
			}
		})
	}
}

func TestBackendIAPEnabledReadsBackendServiceIAP(t *testing.T) {
	if backendIAPEnabled(&computepb.BackendService{}) {
		t.Fatal("backend without IAP enabled returned true")
	}
	backend := &computepb.BackendService{Iap: &computepb.BackendServiceIAP{Enabled: ptrBool(true)}}
	if !backendIAPEnabled(backend) {
		t.Fatal("backend with IAP enabled returned false")
	}
}

func TestBackendSecurityPolicyReadsCloudArmorPolicy(t *testing.T) {
	backend := &computepb.BackendService{
		SecurityPolicy: ptrString("https://www.googleapis.com/compute/v1/projects/proj/global/securityPolicies/prod-armor"),
	}
	if got := backendSecurityPolicy(backend); got != "prod-armor" {
		t.Fatalf("backendSecurityPolicy() = %q, want prod-armor", got)
	}
}

func TestURLMapBackendServicesIncludesRouteRulesAndDeduplicates(t *testing.T) {
	urlMap := &computepb.UrlMap{
		DefaultService: ptrString("https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/default"),
		PathMatchers: []*computepb.PathMatcher{{
			DefaultService: ptrString("https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/default"),
			PathRules: []*computepb.PathRule{{
				Service: ptrString("https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/path"),
			}},
		}},
	}

	got := backendServiceURLsFromURLMap(urlMap)
	if len(got) != 2 {
		t.Fatalf("backendServiceURLsFromURLMap returned %d urls, want 2: %#v", len(got), got)
	}
	if got[0] != "https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/default" {
		t.Fatalf("got[0] = %q", got[0])
	}
	if got[1] != "https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/path" {
		t.Fatalf("got[1] = %q", got[1])
	}
}

func ptrString(value string) *string {
	return &value
}

func ptrBool(value bool) *bool {
	return &value
}
