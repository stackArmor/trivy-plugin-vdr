package cloudrun

import (
	"context"
	"fmt"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func AnalyzeExposure(ctx context.Context, inventory *model.Inventory, services []Service, jobs []Job, client ExposureClient) (map[model.ResourceRef]model.Exposure, []string, error) {
	result := map[model.ResourceRef]model.Exposure{}
	refs := containerRefsByResource(inventory)

	for _, job := range jobs {
		exposure := model.Exposure{
			InternetAccessible: false,
			Provider:           Provider,
			RouteKind:          "CloudRunJob",
			RouteName:          job.Name,
			Evidence:           []string{fmt.Sprintf("Cloud Run Job %s/%s is not internet reachable", job.Region, job.Name)},
		}
		applyExposure(result, refs[jobResourceKey(job.Project, job.Region, job.Name)], exposure)
	}

	if len(services) == 0 {
		return result, nil, nil
	}
	if client == nil {
		return result, []string{"cloudrun exposure analysis skipped services: no exposure client configured"}, nil
	}

	routes, routeWarnings := loadBalancerRoutes(ctx, client, services)
	var warnings []string
	warnings = append(warnings, routeWarnings...)

	for _, service := range services {
		exposure, serviceWarnings := analyzeServiceExposure(ctx, service, routes, client)
		warnings = append(warnings, serviceWarnings...)
		applyExposure(result, refs[serviceResourceKey(service.Project, service.Region, service.Name)], exposure)
	}
	return result, warnings, nil
}

func loadBalancerRoutes(ctx context.Context, client ExposureClient, services []Service) ([]LoadBalancerRoute, []string) {
	needsRoutes := false
	projects := map[string]struct{}{}
	for _, service := range services {
		if service.Ingress == "internal-and-cloud-load-balancing" {
			needsRoutes = true
			projects[service.Project] = struct{}{}
		}
	}
	if !needsRoutes {
		return nil, nil
	}
	var routes []LoadBalancerRoute
	var warnings []string
	for project := range projects {
		projectRoutes, err := client.ListLoadBalancerRoutes(ctx, project)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cloudrun exposure skipped load balancer routes in project %s: %v", project, err))
			continue
		}
		routes = append(routes, projectRoutes...)
	}
	return routes, warnings
}

func analyzeServiceExposure(ctx context.Context, service Service, routes []LoadBalancerRoute, client ExposureClient) (model.Exposure, []string) {
	exposure := model.Exposure{
		InternetAccessible: false,
		Provider:           Provider,
		RouteKind:          "CloudRunService",
		RouteName:          service.Name,
		Evidence:           []string{fmt.Sprintf("Cloud Run Service %s/%s ingress is %q", service.Region, service.Name, service.Ingress)},
	}

	switch service.Ingress {
	case "all":
		if service.InvokerIAMDisabled {
			exposure.InternetAccessible = true
			exposure.Evidence = append(exposure.Evidence, fmt.Sprintf("Cloud Run Service %s/%s Invoker IAM check is disabled", service.Region, service.Name))
			return exposure, nil
		}
		policy, err := client.GetServicePolicy(ctx, service.Project, service.Region, service.Name)
		if err != nil {
			return exposure, []string{fmt.Sprintf("cloudrun exposure skipped IAM policy for service %s/%s: %v", service.Region, service.Name, err)}
		}
		if hasAllUsersInvoker(policy) {
			exposure.InternetAccessible = true
			exposure.Evidence = append(exposure.Evidence, fmt.Sprintf("Cloud Run Service %s/%s allUsers has roles/run.invoker", service.Region, service.Name))
			return exposure, nil
		}
		exposure.Evidence = append(exposure.Evidence, fmt.Sprintf("Cloud Run Service %s/%s does not grant allUsers roles/run.invoker", service.Region, service.Name))
		return exposure, nil
	case "internal-and-cloud-load-balancing":
		return applyLoadBalancerExposure(service, routes, exposure), nil
	case "internal":
		exposure.Evidence = append(exposure.Evidence, fmt.Sprintf("Cloud Run Service %s/%s only allows internal ingress", service.Region, service.Name))
		return exposure, nil
	default:
		exposure.Evidence = append(exposure.Evidence, fmt.Sprintf("Cloud Run Service %s/%s ingress is not a known public mode", service.Region, service.Name))
		return exposure, nil
	}
}

func applyLoadBalancerExposure(service Service, routes []LoadBalancerRoute, exposure model.Exposure) model.Exposure {
	var protected *model.Exposure
	for _, route := range routes {
		if !routeTargetsService(route, service) {
			continue
		}
		if !isPublicLoadBalancingScheme(route.Scheme) {
			continue
		}
		candidate := exposure
		candidate.RouteKind = "LoadBalancer"
		candidate.RouteName = route.Name
		candidate.Routes = []model.RouteMetadata{loadBalancerRouteMetadata(route)}
		candidate.Evidence = append(candidate.Evidence,
			fmt.Sprintf("external load balancer %s routes to serverless NEG %s", route.Name, route.ServerlessNEG),
		)
		applyCloudArmorPolicy(&candidate, route)
		if route.IAPEnabled {
			var securityPolicy *model.SecurityPolicy
			if candidate.Protection != nil {
				securityPolicy = candidate.Protection.SecurityPolicy
			}
			candidate.InternetAccessible = false
			candidate.Protection = &model.AccessProtection{
				Type:           "iap",
				Enabled:        true,
				Provider:       "gcp",
				Evidence:       fmt.Sprintf("backend service %s has IAP enabled", route.BackendService),
				SecurityPolicy: securityPolicy,
			}
			candidate.Evidence = append(candidate.Evidence, fmt.Sprintf("backend service %s has IAP enabled", route.BackendService))
			if protected == nil {
				protected = &candidate
			}
			continue
		}
		candidate.InternetAccessible = true
		candidate.Evidence = append(candidate.Evidence, fmt.Sprintf("backend service %s has IAP disabled", route.BackendService))
		return candidate
	}
	if protected != nil {
		return *protected
	}
	exposure.Evidence = append(exposure.Evidence, fmt.Sprintf("Cloud Run Service %s/%s has no public load balancer route found", service.Region, service.Name))
	return exposure
}

func loadBalancerRouteMetadata(route LoadBalancerRoute) model.RouteMetadata {
	backendService := route.BackendReference
	if backendService == "" {
		backendService = route.BackendService
	}
	return model.RouteMetadata{
		Kind:           "LoadBalancer",
		Name:           route.Name,
		Hostnames:      append([]string(nil), route.Hostnames...),
		Paths:          append([]model.RoutePath(nil), route.Paths...),
		Headers:        append([]model.RouteHeader(nil), route.Headers...),
		Rewrites:       append([]model.RouteRewrite(nil), route.PathRedirects...),
		BackendService: backendService,
		URLMap:         route.URLMap,
		TargetProxy:    route.TargetProxy,
		LoadBalancerIP: route.IPAddress,
	}
}

func applyCloudArmorPolicy(exposure *model.Exposure, route LoadBalancerRoute) {
	if route.CloudArmorPolicy == "" {
		return
	}
	evidence := fmt.Sprintf("backend service %s has Cloud Armor policy %s", route.BackendService, route.CloudArmorPolicy)
	if exposure.Protection == nil {
		exposure.Protection = &model.AccessProtection{Provider: "gcp"}
	}
	exposure.Protection.SecurityPolicy = &model.SecurityPolicy{
		Type:     "cloud-armor",
		Name:     route.CloudArmorPolicy,
		Provider: "gcp",
		Evidence: evidence,
	}
	exposure.Evidence = append(exposure.Evidence, evidence)
}

func hasAllUsersInvoker(bindings []PolicyBinding) bool {
	for _, binding := range bindings {
		if binding.Role != "roles/run.invoker" && binding.Role != "run.invoker" {
			continue
		}
		for _, member := range binding.Members {
			if member == "allUsers" {
				return true
			}
		}
	}
	return false
}

func routeTargetsService(route LoadBalancerRoute, service Service) bool {
	return route.CloudRunService == service.Name && route.CloudRunRegion == service.Region
}

func isPublicLoadBalancingScheme(scheme string) bool {
	switch strings.ToUpper(scheme) {
	case "EXTERNAL", "EXTERNAL_MANAGED":
		return true
	default:
		return false
	}
}

func applyExposure(result map[model.ResourceRef]model.Exposure, refs []model.ResourceRef, exposure model.Exposure) {
	for _, ref := range refs {
		result[ref] = exposure
	}
}

func containerRefsByResource(inventory *model.Inventory) map[string][]model.ResourceRef {
	refs := map[string][]model.ResourceRef{}
	if inventory == nil {
		return refs
	}
	for _, image := range inventory.Images {
		for _, ref := range image.Resources {
			refs[resourceKey(ref)] = append(refs[resourceKey(ref)], ref)
		}
	}
	if len(refs) > 0 {
		return refs
	}
	for _, resource := range inventory.Resources {
		key := resourceKey(resource.Resource)
		for _, image := range resource.Images {
			ref := resource.Resource
			ref.ContainerName = image.Name
			ref.ContainerType = image.ContainerType
			ref.RestartPolicy = image.RestartPolicy
			refs[key] = append(refs[key], ref)
		}
	}
	return refs
}

func serviceResourceKey(project, region, name string) string {
	return resourceKey(model.ResourceRef{Kind: "Service", Provider: Provider, Project: project, Region: region, Name: name})
}

func jobResourceKey(project, region, name string) string {
	return resourceKey(model.ResourceRef{Kind: "Job", Provider: Provider, Project: project, Region: region, Name: name})
}

func resourceKey(ref model.ResourceRef) string {
	return strings.Join([]string{ref.Provider, ref.Project, ref.Region, ref.Kind, ref.Name}, "\x00")
}
