package cloudrun

import (
	"context"
	"testing"

	"cloud.google.com/go/compute/apiv1/computepb"
	"golang.org/x/oauth2"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
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

func TestClientOptionsUseImpersonatedServiceAccount(t *testing.T) {
	var gotTarget string
	original := impersonateCredentialsTokenSource
	impersonateCredentialsTokenSource = func(_ context.Context, config impersonate.CredentialsConfig, _ ...option.ClientOption) (oauth2.TokenSource, error) {
		gotTarget = config.TargetPrincipal
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}), nil
	}
	t.Cleanup(func() { impersonateCredentialsTokenSource = original })

	opts, err := clientOptions(context.Background(), ClientOptions{ImpersonateServiceAccount: "vdr-reader@example.iam.gserviceaccount.com"})
	if err != nil {
		t.Fatalf("clientOptions returned error: %v", err)
	}
	if len(opts) == 0 {
		t.Fatal("clientOptions returned no options, want impersonation option")
	}
	if gotTarget != "vdr-reader@example.iam.gserviceaccount.com" {
		t.Fatalf("TargetPrincipal = %q", gotTarget)
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

func TestURLMapRouteMetadataIncludesHostsPathsAndRewrites(t *testing.T) {
	urlMap := &computepb.UrlMap{
		HostRules: []*computepb.HostRule{{
			Hosts:       []string{"api.example.com"},
			PathMatcher: ptrString("api-matcher"),
		}},
		PathMatchers: []*computepb.PathMatcher{{
			Name: ptrString("api-matcher"),
			PathRules: []*computepb.PathRule{{
				Paths:   []string{"/api/*"},
				Service: ptrString("https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/api-backend"),
				RouteAction: &computepb.HttpRouteAction{UrlRewrite: &computepb.UrlRewrite{
					PathPrefixRewrite: ptrString("/"),
				}},
			}},
		}},
	}

	got := routeMetadataByBackendURLFromURLMap(urlMap)

	metadata := got["https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/api-backend"]
	if len(metadata.Hostnames) != 1 || metadata.Hostnames[0] != "api.example.com" {
		t.Fatalf("Hostnames = %#v, want api.example.com", metadata.Hostnames)
	}
	if len(metadata.Paths) != 1 || metadata.Paths[0].Value != "/api/*" {
		t.Fatalf("Paths = %#v, want /api/*", metadata.Paths)
	}
	if len(metadata.PathRedirects) != 1 || metadata.PathRedirects[0].PathReplacePrefixMatch != "/" {
		t.Fatalf("PathRedirects = %#v, want prefix rewrite /", metadata.PathRedirects)
	}
}

func ptrString(value string) *string {
	return &value
}

func ptrBool(value bool) *bool {
	return &value
}
