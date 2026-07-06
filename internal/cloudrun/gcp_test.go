package cloudrun

import (
	"context"
	"testing"

	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/run/apiv2/runpb"
	"golang.org/x/oauth2"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	runv1 "google.golang.org/api/run/v1"
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

func TestServiceFromPBReadsInvokerIAMDisabled(t *testing.T) {
	service := serviceFromPB("p", "us-east4", &runpb.Service{
		Name:               "projects/p/locations/us-east4/services/api",
		Ingress:            runpb.IngressTraffic_INGRESS_TRAFFIC_ALL,
		InvokerIamDisabled: true,
	})

	if service.Ingress != "all" {
		t.Fatalf("Ingress = %q, want all", service.Ingress)
	}
	if !service.InvokerIAMDisabled {
		t.Fatalf("InvokerIAMDisabled = false, want true")
	}
}

func TestServiceFromV1DefaultsMissingIngressToAllAndReadsInvokerIAMDisabledAnnotation(t *testing.T) {
	service := serviceFromV1("p", "us-east4", &runv1.Service{
		Metadata: &runv1.ObjectMeta{
			Name: "api",
			Annotations: map[string]string{
				"run.googleapis.com/invoker-iam-disabled": "true",
			},
		},
	})

	if service.Ingress != "all" {
		t.Fatalf("Ingress = %q, want all when v1 annotation is absent", service.Ingress)
	}
	if !service.InvokerIAMDisabled {
		t.Fatalf("InvokerIAMDisabled = false, want true")
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

func TestURLMapRouteMetadataIncludesRouteRuleMatchesAndRewrites(t *testing.T) {
	urlMap := &computepb.UrlMap{
		HostRules: []*computepb.HostRule{{
			Hosts:       []string{"api.example.com"},
			PathMatcher: ptrString("api-matcher"),
		}},
		PathMatchers: []*computepb.PathMatcher{{
			Name: ptrString("api-matcher"),
			RouteRules: []*computepb.HttpRouteRule{{
				Service: ptrString("https://www.googleapis.com/compute/v1/projects/proj/global/backendServices/api-backend"),
				MatchRules: []*computepb.HttpRouteRuleMatch{{
					PrefixMatch: ptrString("/api"),
					HeaderMatches: []*computepb.HttpHeaderMatch{{
						HeaderName: ptrString("x-env"),
						ExactMatch: ptrString("prod"),
					}},
				}},
				RouteAction: &computepb.HttpRouteAction{UrlRewrite: &computepb.UrlRewrite{
					HostRewrite:       ptrString("backend.example.internal"),
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
	if len(metadata.Paths) != 1 || metadata.Paths[0].Type != "PrefixMatch" || metadata.Paths[0].Value != "/api" {
		t.Fatalf("Paths = %#v, want PrefixMatch /api", metadata.Paths)
	}
	if len(metadata.Headers) != 1 || metadata.Headers[0].Type != "ExactMatch" || metadata.Headers[0].Name != "x-env" || metadata.Headers[0].Value != "prod" {
		t.Fatalf("Headers = %#v, want exact x-env=prod", metadata.Headers)
	}
	if len(metadata.PathRedirects) != 1 || metadata.PathRedirects[0].HostnameReplace != "backend.example.internal" || metadata.PathRedirects[0].PathReplacePrefixMatch != "/" {
		t.Fatalf("PathRedirects = %#v, want host and prefix rewrite", metadata.PathRedirects)
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
