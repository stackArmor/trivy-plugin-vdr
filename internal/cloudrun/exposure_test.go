package cloudrun

import (
	"context"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestAnalyzeExposureMarksJobsPrivate(t *testing.T) {
	job := Job{
		Project:    "p",
		Region:     "us-east4",
		Name:       "nightly",
		Containers: []Container{{Name: "worker", Image: "example.com/worker:1"}},
	}
	inventory := inventoryForExposure(t, nil, []Job{job})

	got, warnings, err := AnalyzeExposure(context.Background(), inventory, nil, []Job{job}, &fakeExposureClient{})
	if err != nil {
		t.Fatalf("AnalyzeExposure returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	ref := cloudRunRef("Job", "p", "us-east4", "nightly", "worker")
	ex := got[ref]
	if ex.InternetAccessible {
		t.Fatalf("job exposure = %#v, want private", ex)
	}
	requireEvidence(t, ex, "Cloud Run Job us-east4/nightly is not internet reachable")
}

func TestAnalyzeExposureMarksAllIngressInvokerServicePublic(t *testing.T) {
	service := Service{
		Project:    "p",
		Region:     "us-east4",
		Name:       "api",
		Ingress:    "all",
		Containers: []Container{{Name: "app", Image: "example.com/api:1"}},
	}
	inventory := inventoryForExposure(t, []Service{service}, nil)
	client := &fakeExposureClient{policies: map[string][]PolicyBinding{
		"p/us-east4/api": {{Role: "roles/run.invoker", Members: []string{"allUsers"}}},
	}}

	got, _, err := AnalyzeExposure(context.Background(), inventory, []Service{service}, nil, client)
	if err != nil {
		t.Fatalf("AnalyzeExposure returned error: %v", err)
	}
	ex := got[cloudRunRef("Service", "p", "us-east4", "api", "app")]
	if !ex.InternetAccessible {
		t.Fatalf("service exposure = %#v, want public", ex)
	}
	requireEvidence(t, ex, "allUsers has roles/run.invoker")
}

func TestAnalyzeExposureDoesNotMarkAllIngressWithoutAllUsers(t *testing.T) {
	service := Service{
		Project:    "p",
		Region:     "us-east4",
		Name:       "api",
		Ingress:    "all",
		Containers: []Container{{Name: "app", Image: "example.com/api:1"}},
	}
	inventory := inventoryForExposure(t, []Service{service}, nil)
	client := &fakeExposureClient{policies: map[string][]PolicyBinding{
		"p/us-east4/api": {{Role: "roles/run.invoker", Members: []string{"user:a@example.com"}}},
	}}

	got, _, err := AnalyzeExposure(context.Background(), inventory, []Service{service}, nil, client)
	if err != nil {
		t.Fatalf("AnalyzeExposure returned error: %v", err)
	}
	ex := got[cloudRunRef("Service", "p", "us-east4", "api", "app")]
	if ex.InternetAccessible {
		t.Fatalf("service exposure = %#v, want private without allUsers invoker", ex)
	}
	requireEvidence(t, ex, "does not grant allUsers roles/run.invoker")
}

func TestAnalyzeExposureMarksInternalLBServicePublicWhenExternalLBNoIAP(t *testing.T) {
	service := Service{
		Project:    "p",
		Region:     "us-east4",
		Name:       "api",
		Ingress:    "internal-and-cloud-load-balancing",
		Containers: []Container{{Name: "app", Image: "example.com/api:1"}},
	}
	inventory := inventoryForExposure(t, []Service{service}, nil)
	client := &fakeExposureClient{routes: []LoadBalancerRoute{{
		Name:            "api-lb",
		Scheme:          "EXTERNAL_MANAGED",
		IPAddress:       "203.0.113.10",
		BackendService:  "api-backend",
		ServerlessNEG:   "api-neg",
		CloudRunService: "api",
		CloudRunRegion:  "us-east4",
		IAPEnabled:      false,
	}}}

	got, _, err := AnalyzeExposure(context.Background(), inventory, []Service{service}, nil, client)
	if err != nil {
		t.Fatalf("AnalyzeExposure returned error: %v", err)
	}
	ex := got[cloudRunRef("Service", "p", "us-east4", "api", "app")]
	if !ex.InternetAccessible {
		t.Fatalf("service exposure = %#v, want public through external LB", ex)
	}
	requireEvidence(t, ex, "external load balancer api-lb routes to serverless NEG api-neg")
	requireEvidence(t, ex, "backend service api-backend has IAP disabled")
}

func TestAnalyzeExposureIncludesCloudArmorPolicyForLoadBalancerBackend(t *testing.T) {
	service := Service{
		Project:    "p",
		Region:     "us-east4",
		Name:       "api",
		Ingress:    "internal-and-cloud-load-balancing",
		Containers: []Container{{Name: "app", Image: "example.com/api:1"}},
	}
	inventory := inventoryForExposure(t, []Service{service}, nil)
	client := &fakeExposureClient{routes: []LoadBalancerRoute{{
		Name:             "api-lb",
		Scheme:           "EXTERNAL_MANAGED",
		BackendService:   "api-backend",
		ServerlessNEG:    "api-neg",
		CloudRunService:  "api",
		CloudRunRegion:   "us-east4",
		CloudArmorPolicy: "prod-armor",
	}}}

	got, _, err := AnalyzeExposure(context.Background(), inventory, []Service{service}, nil, client)
	if err != nil {
		t.Fatalf("AnalyzeExposure returned error: %v", err)
	}
	ex := got[cloudRunRef("Service", "p", "us-east4", "api", "app")]
	if !ex.InternetAccessible {
		t.Fatalf("service exposure = %#v, want public through external LB", ex)
	}
	if ex.Protection == nil || ex.Protection.SecurityPolicy == nil {
		t.Fatalf("protection = %#v, want Cloud Armor security policy visibility", ex.Protection)
	}
	if ex.Protection.SecurityPolicy.Type != "cloud-armor" || ex.Protection.SecurityPolicy.Name != "prod-armor" {
		t.Fatalf("security policy = %#v, want Cloud Armor prod-armor", ex.Protection.SecurityPolicy)
	}
	requireEvidence(t, ex, "backend service api-backend has Cloud Armor policy prod-armor")
}

func TestAnalyzeExposureTreatsIAPBackendAsProtected(t *testing.T) {
	service := Service{
		Project:    "p",
		Region:     "us-east4",
		Name:       "api",
		Ingress:    "internal-and-cloud-load-balancing",
		Containers: []Container{{Name: "app", Image: "example.com/api:1"}},
	}
	inventory := inventoryForExposure(t, []Service{service}, nil)
	client := &fakeExposureClient{routes: []LoadBalancerRoute{{
		Name:            "api-lb",
		Scheme:          "EXTERNAL_MANAGED",
		BackendService:  "api-backend",
		ServerlessNEG:   "api-neg",
		CloudRunService: "api",
		CloudRunRegion:  "us-east4",
		IAPEnabled:      true,
	}}}

	got, _, err := AnalyzeExposure(context.Background(), inventory, []Service{service}, nil, client)
	if err != nil {
		t.Fatalf("AnalyzeExposure returned error: %v", err)
	}
	ex := got[cloudRunRef("Service", "p", "us-east4", "api", "app")]
	if ex.InternetAccessible {
		t.Fatalf("service exposure = %#v, want protected/private", ex)
	}
	if ex.Protection == nil || ex.Protection.Type != "iap" || !ex.Protection.Enabled {
		t.Fatalf("protection = %#v, want enabled IAP", ex.Protection)
	}
	requireEvidence(t, ex, "backend service api-backend has IAP enabled")
}

func TestAnalyzeExposureIgnoresInternalForwardingRule(t *testing.T) {
	service := Service{
		Project:    "p",
		Region:     "us-east4",
		Name:       "api",
		Ingress:    "internal-and-cloud-load-balancing",
		Containers: []Container{{Name: "app", Image: "example.com/api:1"}},
	}
	inventory := inventoryForExposure(t, []Service{service}, nil)
	client := &fakeExposureClient{routes: []LoadBalancerRoute{{
		Name:            "api-lb",
		Scheme:          "INTERNAL_MANAGED",
		BackendService:  "api-backend",
		ServerlessNEG:   "api-neg",
		CloudRunService: "api",
		CloudRunRegion:  "us-east4",
	}}}

	got, _, err := AnalyzeExposure(context.Background(), inventory, []Service{service}, nil, client)
	if err != nil {
		t.Fatalf("AnalyzeExposure returned error: %v", err)
	}
	ex := got[cloudRunRef("Service", "p", "us-east4", "api", "app")]
	if ex.InternetAccessible {
		t.Fatalf("service exposure = %#v, want private with internal LB", ex)
	}
	requireEvidence(t, ex, "no public load balancer route found")
}

func inventoryForExposure(t *testing.T, services []Service, jobs []Job) *model.Inventory {
	t.Helper()
	client := &fakeInventoryClient{
		services: map[string][]Service{"us-east4": services},
		jobs:     map[string][]Job{"us-east4": jobs},
	}
	inv, err := (Collector{Client: client}).Collect(context.Background(), Options{Project: "p", Regions: []string{"us-east4"}})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	return inv
}

func cloudRunRef(kind, project, region, name, container string) model.ResourceRef {
	return model.ResourceRef{
		APIVersion:    "run.googleapis.com/v1",
		Kind:          kind,
		Provider:      Provider,
		Project:       project,
		Region:        region,
		Name:          name,
		ContainerName: container,
		ContainerType: "container",
	}
}

type fakeExposureClient struct {
	policies map[string][]PolicyBinding
	routes   []LoadBalancerRoute
}

func (f *fakeExposureClient) GetServicePolicy(ctx context.Context, project, region, service string) ([]PolicyBinding, error) {
	return append([]PolicyBinding(nil), f.policies[project+"/"+region+"/"+service]...), nil
}

func (f *fakeExposureClient) ListLoadBalancerRoutes(ctx context.Context, project string) ([]LoadBalancerRoute, error) {
	return append([]LoadBalancerRoute(nil), f.routes...), nil
}

func requireEvidence(t *testing.T, exposure model.Exposure, want string) {
	t.Helper()
	for _, got := range exposure.Evidence {
		if strings.Contains(got, want) {
			return
		}
	}
	t.Fatalf("missing evidence %q in %#v", want, exposure.Evidence)
}
