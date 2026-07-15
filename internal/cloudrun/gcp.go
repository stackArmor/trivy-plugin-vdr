package cloudrun

import (
	"context"
	"fmt"
	"path"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	run "cloud.google.com/go/run/apiv2"
	"cloud.google.com/go/run/apiv2/runpb"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	runv1 "google.golang.org/api/run/v1"
)

type GCPClient struct {
	servicesV1              *runv1.APIService
	services                *run.ServicesClient
	jobs                    *run.JobsClient
	projects                *resourcemanager.ProjectsClient
	regions                 *compute.RegionsClient
	globalForwardingRules   *compute.GlobalForwardingRulesClient
	regionalForwardingRules *compute.ForwardingRulesClient
	targetHTTPProxies       *compute.TargetHttpProxiesClient
	targetHTTPSProxies      *compute.TargetHttpsProxiesClient
	regionTargetHTTP        *compute.RegionTargetHttpProxiesClient
	regionTargetHTTPS       *compute.RegionTargetHttpsProxiesClient
	urlMaps                 *compute.UrlMapsClient
	regionURLMaps           *compute.RegionUrlMapsClient
	backendServices         *compute.BackendServicesClient
	regionBackendServices   *compute.RegionBackendServicesClient
	regionNEGs              *compute.RegionNetworkEndpointGroupsClient
}

type ClientOptions struct {
	ImpersonateServiceAccount string
}

var impersonateCredentialsTokenSource = impersonate.CredentialsTokenSource

func NewGCPClient(ctx context.Context, options ...ClientOptions) (*GCPClient, error) {
	var clientOptions ClientOptions
	if len(options) > 0 {
		clientOptions = options[0]
	}
	opts, err := clientOptionsForCloudRun(ctx, clientOptions)
	if err != nil {
		return nil, err
	}
	servicesV1, err := runv1.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create cloud run v1 service client: %w", err)
	}
	services, err := run.NewServicesClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create cloud run services client: %w", err)
	}
	jobs, err := run.NewJobsClient(ctx, opts...)
	if err != nil {
		services.Close()
		return nil, fmt.Errorf("create cloud run jobs client: %w", err)
	}
	projects, err := resourcemanager.NewProjectsClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		return nil, fmt.Errorf("create resource manager projects client: %w", err)
	}
	regions, err := compute.NewRegionsRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		return nil, fmt.Errorf("create compute regions client: %w", err)
	}
	globalForwardingRules, err := compute.NewGlobalForwardingRulesRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		return nil, fmt.Errorf("create global forwarding rules client: %w", err)
	}
	regionalForwardingRules, err := compute.NewForwardingRulesRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		return nil, fmt.Errorf("create forwarding rules client: %w", err)
	}
	targetHTTPProxies, err := compute.NewTargetHttpProxiesRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		return nil, fmt.Errorf("create target http proxies client: %w", err)
	}
	targetHTTPSProxies, err := compute.NewTargetHttpsProxiesRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		targetHTTPProxies.Close()
		return nil, fmt.Errorf("create target https proxies client: %w", err)
	}
	regionTargetHTTP, err := compute.NewRegionTargetHttpProxiesRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		targetHTTPProxies.Close()
		targetHTTPSProxies.Close()
		return nil, fmt.Errorf("create regional target http proxies client: %w", err)
	}
	regionTargetHTTPS, err := compute.NewRegionTargetHttpsProxiesRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		targetHTTPProxies.Close()
		targetHTTPSProxies.Close()
		regionTargetHTTP.Close()
		return nil, fmt.Errorf("create regional target https proxies client: %w", err)
	}
	urlMaps, err := compute.NewUrlMapsRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		targetHTTPProxies.Close()
		targetHTTPSProxies.Close()
		regionTargetHTTP.Close()
		regionTargetHTTPS.Close()
		return nil, fmt.Errorf("create url maps client: %w", err)
	}
	regionURLMaps, err := compute.NewRegionUrlMapsRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		targetHTTPProxies.Close()
		targetHTTPSProxies.Close()
		regionTargetHTTP.Close()
		regionTargetHTTPS.Close()
		urlMaps.Close()
		return nil, fmt.Errorf("create regional url maps client: %w", err)
	}
	backendServices, err := compute.NewBackendServicesRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		targetHTTPProxies.Close()
		targetHTTPSProxies.Close()
		regionTargetHTTP.Close()
		regionTargetHTTPS.Close()
		urlMaps.Close()
		regionURLMaps.Close()
		return nil, fmt.Errorf("create backend services client: %w", err)
	}
	regionBackendServices, err := compute.NewRegionBackendServicesRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		targetHTTPProxies.Close()
		targetHTTPSProxies.Close()
		regionTargetHTTP.Close()
		regionTargetHTTPS.Close()
		urlMaps.Close()
		regionURLMaps.Close()
		backendServices.Close()
		return nil, fmt.Errorf("create regional backend services client: %w", err)
	}
	regionNEGs, err := compute.NewRegionNetworkEndpointGroupsRESTClient(ctx, opts...)
	if err != nil {
		services.Close()
		jobs.Close()
		projects.Close()
		regions.Close()
		globalForwardingRules.Close()
		regionalForwardingRules.Close()
		targetHTTPProxies.Close()
		targetHTTPSProxies.Close()
		regionTargetHTTP.Close()
		regionTargetHTTPS.Close()
		urlMaps.Close()
		regionURLMaps.Close()
		backendServices.Close()
		regionBackendServices.Close()
		return nil, fmt.Errorf("create regional network endpoint groups client: %w", err)
	}
	return &GCPClient{
		servicesV1:              servicesV1,
		services:                services,
		jobs:                    jobs,
		projects:                projects,
		regions:                 regions,
		globalForwardingRules:   globalForwardingRules,
		regionalForwardingRules: regionalForwardingRules,
		targetHTTPProxies:       targetHTTPProxies,
		targetHTTPSProxies:      targetHTTPSProxies,
		regionTargetHTTP:        regionTargetHTTP,
		regionTargetHTTPS:       regionTargetHTTPS,
		urlMaps:                 urlMaps,
		regionURLMaps:           regionURLMaps,
		backendServices:         backendServices,
		regionBackendServices:   regionBackendServices,
		regionNEGs:              regionNEGs,
	}, nil
}

func clientOptions(ctx context.Context, options ClientOptions) ([]option.ClientOption, error) {
	return clientOptionsForCloudRun(ctx, options)
}

func clientOptionsForCloudRun(ctx context.Context, options ClientOptions) ([]option.ClientOption, error) {
	if options.ImpersonateServiceAccount == "" {
		return nil, nil
	}
	tokenSource, err := impersonateCredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: options.ImpersonateServiceAccount,
		Scopes: []string{
			"https://www.googleapis.com/auth/cloud-platform",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create impersonated Google credentials for %s: %w", options.ImpersonateServiceAccount, err)
	}
	return []option.ClientOption{option.WithTokenSource(tokenSource)}, nil
}

func (c *GCPClient) Close() error {
	if c == nil {
		return nil
	}
	var errs []string
	closeClient := func(name string, err error) {
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	closeClient("cloud run services", c.services.Close())
	closeClient("cloud run jobs", c.jobs.Close())
	closeClient("resource manager projects", c.projects.Close())
	closeClient("compute regions", c.regions.Close())
	closeClient("global forwarding rules", c.globalForwardingRules.Close())
	closeClient("forwarding rules", c.regionalForwardingRules.Close())
	closeClient("target http proxies", c.targetHTTPProxies.Close())
	closeClient("target https proxies", c.targetHTTPSProxies.Close())
	closeClient("regional target http proxies", c.regionTargetHTTP.Close())
	closeClient("regional target https proxies", c.regionTargetHTTPS.Close())
	closeClient("url maps", c.urlMaps.Close())
	closeClient("regional url maps", c.regionURLMaps.Close())
	closeClient("backend services", c.backendServices.Close())
	closeClient("regional backend services", c.regionBackendServices.Close())
	closeClient("regional network endpoint groups", c.regionNEGs.Close())
	if len(errs) > 0 {
		return fmt.Errorf("close gcp clients: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (c *GCPClient) ListServices(ctx context.Context, project, region string) ([]Service, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s", project, region)
	resp, err := c.servicesV1.Namespaces.Services.List(parent).Context(ctx).Do()
	if err == nil {
		services := make([]Service, 0, len(resp.Items))
		for _, service := range resp.Items {
			services = append(services, serviceFromV1(project, region, service))
		}
		return services, nil
	}

	it := c.services.ListServices(ctx, &runpb.ListServicesRequest{Parent: parent})
	var services []Service
	for {
		service, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		services = append(services, serviceFromPB(project, region, service))
	}
	return services, nil
}

func (c *GCPClient) ListJobs(ctx context.Context, project, region string) ([]Job, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s", project, region)
	it := c.jobs.ListJobs(ctx, &runpb.ListJobsRequest{Parent: parent})
	var jobs []Job
	for {
		job, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, jobFromPB(project, region, job))
	}
	return jobs, nil
}

func (c *GCPClient) GetProjectLabels(ctx context.Context, project string) (map[string]string, error) {
	resourceProject, err := c.projects.GetProject(ctx, &resourcemanagerpb.GetProjectRequest{Name: "projects/" + project})
	if err != nil {
		return nil, err
	}
	return copyStringMap(resourceProject.GetLabels()), nil
}

func (c *GCPClient) GetServicePolicy(ctx context.Context, project, region, service string) ([]PolicyBinding, error) {
	resource := fmt.Sprintf("projects/%s/locations/%s/services/%s", project, region, service)
	policy, err := c.services.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resource})
	if err != nil {
		return nil, err
	}
	bindings := make([]PolicyBinding, 0, len(policy.GetBindings()))
	for _, binding := range policy.GetBindings() {
		bindings = append(bindings, PolicyBinding{
			Role:    binding.GetRole(),
			Members: append([]string(nil), binding.GetMembers()...),
		})
	}
	return bindings, nil
}

func (c *GCPClient) ListLoadBalancerRoutes(ctx context.Context, project string) ([]LoadBalancerRoute, error) {
	var routes []LoadBalancerRoute
	globalRoutes, err := c.listGlobalLoadBalancerRoutes(ctx, project)
	if err != nil {
		return nil, err
	}
	routes = append(routes, globalRoutes...)
	regions, err := c.listRegions(ctx, project)
	if err != nil {
		return nil, err
	}
	for _, region := range regions {
		regionRoutes, err := c.listRegionalLoadBalancerRoutes(ctx, project, region)
		if err != nil {
			return nil, err
		}
		routes = append(routes, regionRoutes...)
	}
	return routes, nil
}

func (c *GCPClient) listGlobalLoadBalancerRoutes(ctx context.Context, project string) ([]LoadBalancerRoute, error) {
	it := c.globalForwardingRules.List(ctx, &computepb.ListGlobalForwardingRulesRequest{Project: project})
	var routes []LoadBalancerRoute
	for {
		rule, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list global forwarding rules: %w", err)
		}
		if !isPublicLoadBalancingScheme(rule.GetLoadBalancingScheme()) {
			continue
		}
		urlMap, err := c.globalURLMapForForwardingRule(ctx, project, rule)
		if err != nil {
			return nil, err
		}
		if urlMap == nil {
			continue
		}
		backendURLs := backendServiceURLsFromURLMap(urlMap)
		routeMetadata := routeMetadataByBackendURLFromURLMap(urlMap)
		for _, backendURL := range backendURLs {
			backend, err := c.backendServices.Get(ctx, &computepb.GetBackendServiceRequest{Project: project, BackendService: path.Base(backendURL)})
			if err != nil {
				return nil, fmt.Errorf("get global backend service %s: %w", path.Base(backendURL), err)
			}
			routeEntries, err := c.routesForBackend(ctx, project, rule, urlMap.GetName(), backend, "", routeMetadata[backendURL])
			if err != nil {
				return nil, err
			}
			routes = append(routes, routeEntries...)
		}
	}
	return routes, nil
}

func (c *GCPClient) listRegionalLoadBalancerRoutes(ctx context.Context, project, region string) ([]LoadBalancerRoute, error) {
	it := c.regionalForwardingRules.List(ctx, &computepb.ListForwardingRulesRequest{Project: project, Region: region})
	var routes []LoadBalancerRoute
	for {
		rule, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list forwarding rules in %s: %w", region, err)
		}
		if !isPublicLoadBalancingScheme(rule.GetLoadBalancingScheme()) {
			continue
		}
		urlMap, err := c.regionalURLMapForForwardingRule(ctx, project, region, rule)
		if err != nil {
			return nil, err
		}
		if urlMap == nil {
			continue
		}
		backendURLs := backendServiceURLsFromURLMap(urlMap)
		routeMetadata := routeMetadataByBackendURLFromURLMap(urlMap)
		for _, backendURL := range backendURLs {
			backendRegion := regionFromURL(backendURL)
			if backendRegion == "" {
				backendRegion = region
			}
			backend, err := c.regionBackendServices.Get(ctx, &computepb.GetRegionBackendServiceRequest{Project: project, Region: backendRegion, BackendService: path.Base(backendURL)})
			if err != nil {
				return nil, fmt.Errorf("get regional backend service %s/%s: %w", backendRegion, path.Base(backendURL), err)
			}
			routeEntries, err := c.routesForBackend(ctx, project, rule, urlMap.GetName(), backend, backendRegion, routeMetadata[backendURL])
			if err != nil {
				return nil, err
			}
			routes = append(routes, routeEntries...)
		}
	}
	return routes, nil
}

func (c *GCPClient) listRegions(ctx context.Context, project string) ([]string, error) {
	it := c.regions.List(ctx, &computepb.ListRegionsRequest{Project: project})
	var regions []string
	for {
		region, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list compute regions: %w", err)
		}
		regions = append(regions, region.GetName())
	}
	return regions, nil
}

func (c *GCPClient) globalURLMapForForwardingRule(ctx context.Context, project string, rule *computepb.ForwardingRule) (*computepb.UrlMap, error) {
	target := rule.GetTarget()
	var urlMapURL string
	switch {
	case strings.Contains(target, "/targetHttpsProxies/"):
		proxy, err := c.targetHTTPSProxies.Get(ctx, &computepb.GetTargetHttpsProxyRequest{Project: project, TargetHttpsProxy: path.Base(target)})
		if err != nil {
			return nil, fmt.Errorf("get global target https proxy %s: %w", path.Base(target), err)
		}
		urlMapURL = proxy.GetUrlMap()
	case strings.Contains(target, "/targetHttpProxies/"):
		proxy, err := c.targetHTTPProxies.Get(ctx, &computepb.GetTargetHttpProxyRequest{Project: project, TargetHttpProxy: path.Base(target)})
		if err != nil {
			return nil, fmt.Errorf("get global target http proxy %s: %w", path.Base(target), err)
		}
		urlMapURL = proxy.GetUrlMap()
	default:
		return nil, nil
	}
	if urlMapURL == "" {
		return nil, nil
	}
	urlMap, err := c.urlMaps.Get(ctx, &computepb.GetUrlMapRequest{Project: project, UrlMap: path.Base(urlMapURL)})
	if err != nil {
		return nil, fmt.Errorf("get global url map %s: %w", path.Base(urlMapURL), err)
	}
	return urlMap, nil
}

func (c *GCPClient) regionalURLMapForForwardingRule(ctx context.Context, project, region string, rule *computepb.ForwardingRule) (*computepb.UrlMap, error) {
	target := rule.GetTarget()
	targetRegion := regionFromURL(target)
	if targetRegion == "" {
		targetRegion = region
	}
	var urlMapURL string
	switch {
	case strings.Contains(target, "/targetHttpsProxies/"):
		proxy, err := c.regionTargetHTTPS.Get(ctx, &computepb.GetRegionTargetHttpsProxyRequest{Project: project, Region: targetRegion, TargetHttpsProxy: path.Base(target)})
		if err != nil {
			return nil, fmt.Errorf("get regional target https proxy %s/%s: %w", targetRegion, path.Base(target), err)
		}
		urlMapURL = proxy.GetUrlMap()
	case strings.Contains(target, "/targetHttpProxies/"):
		proxy, err := c.regionTargetHTTP.Get(ctx, &computepb.GetRegionTargetHttpProxyRequest{Project: project, Region: targetRegion, TargetHttpProxy: path.Base(target)})
		if err != nil {
			return nil, fmt.Errorf("get regional target http proxy %s/%s: %w", targetRegion, path.Base(target), err)
		}
		urlMapURL = proxy.GetUrlMap()
	default:
		return nil, nil
	}
	if urlMapURL == "" {
		return nil, nil
	}
	urlMapRegion := regionFromURL(urlMapURL)
	if urlMapRegion == "" {
		urlMapRegion = targetRegion
	}
	urlMap, err := c.regionURLMaps.Get(ctx, &computepb.GetRegionUrlMapRequest{Project: project, Region: urlMapRegion, UrlMap: path.Base(urlMapURL)})
	if err != nil {
		return nil, fmt.Errorf("get regional url map %s/%s: %w", urlMapRegion, path.Base(urlMapURL), err)
	}
	return urlMap, nil
}

func (c *GCPClient) routesForBackend(ctx context.Context, project string, rule *computepb.ForwardingRule, urlMapName string, backend *computepb.BackendService, backendRegion string, metadata LoadBalancerRoute) ([]LoadBalancerRoute, error) {
	var routes []LoadBalancerRoute
	for _, backendEndpoint := range backend.GetBackends() {
		group := backendEndpoint.GetGroup()
		region := regionFromURL(group)
		if region == "" {
			continue
		}
		neg, err := c.regionNEGs.Get(ctx, &computepb.GetRegionNetworkEndpointGroupRequest{Project: project, Region: region, NetworkEndpointGroup: path.Base(group)})
		if err != nil {
			return nil, fmt.Errorf("get regional network endpoint group %s/%s: %w", region, path.Base(group), err)
		}
		service, serviceRegion, ok := cloudRunServiceFromNEG(neg)
		if !ok {
			continue
		}
		if serviceRegion == "" {
			serviceRegion = region
		}
		route := metadata
		route.Name = rule.GetName()
		route.Scheme = rule.GetLoadBalancingScheme()
		route.IPAddress = rule.GetIPAddress()
		route.TargetProxy = path.Base(rule.GetTarget())
		route.URLMap = urlMapName
		route.BackendService = backend.GetName()
		route.ServerlessNEG = neg.GetName()
		route.CloudRunService = service
		route.CloudRunRegion = serviceRegion
		route.IAPEnabled = backendIAPEnabled(backend)
		route.IAPOAuth2ClientID = backend.GetIap().GetOauth2ClientId()
		route.CloudArmorPolicy = backendSecurityPolicy(backend)
		route.BackendServiceRegion = backendRegion
		if route.BackendReference == "" {
			route.BackendReference = backend.GetName()
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func serviceFromPB(project, region string, service *runpb.Service) Service {
	return Service{
		Project:            project,
		Region:             region,
		Name:               path.Base(service.GetName()),
		Ingress:            ingressFromPB(service.GetIngress()),
		URI:                service.GetUri(),
		InvokerIAMDisabled: service.GetInvokerIamDisabled(),
		ExecutionEnvironment: executionEnvironmentFromPB(service.GetTemplate().GetExecutionEnvironment()),
		Labels:               copyStringMap(service.GetLabels()),
		Annotations:          copyStringMap(service.GetAnnotations()),
		Containers:           containersFromPB(service.GetTemplate().GetContainers()),
	}
}

func executionEnvironmentFromPB(env runpb.ExecutionEnvironment) string {
	switch env {
	case runpb.ExecutionEnvironment_EXECUTION_ENVIRONMENT_GEN1:
		return "gen1"
	case runpb.ExecutionEnvironment_EXECUTION_ENVIRONMENT_GEN2:
		return "gen2"
	default:
		return ""
	}
}

func serviceFromV1(project, region string, service *runv1.Service) Service {
	if service == nil {
		return Service{Project: project, Region: region}
	}
	var name string
	var labels map[string]string
	var annotations map[string]string
	if service.Metadata != nil {
		name = service.Metadata.Name
		labels = service.Metadata.Labels
		annotations = service.Metadata.Annotations
	}
	var templateSpec *runv1.RevisionSpec
	if service.Spec != nil && service.Spec.Template != nil {
		templateSpec = service.Spec.Template.Spec
	}
	return Service{
		Project:              project,
		Region:               region,
		Name:                 path.Base(name),
		Ingress:              ingressFromAnnotation(annotations["run.googleapis.com/ingress"]),
		URI:                  serviceURLV1(service),
		RuntimeClassName:     runtimeClassNameV1(templateSpec),
		InvokerIAMDisabled:   parseBoolAnnotation(annotations["run.googleapis.com/invoker-iam-disabled"]),
		ExecutionEnvironment: executionEnvironmentV1(service),
		Labels:               copyStringMap(labels),
		Annotations:          copyStringMap(annotations),
		Containers:           containersFromV1(templateSpec),
	}
}

// executionEnvironmentV1 reads the explicit execution environment from the
// revision template annotation ("gen1"/"gen2"); empty means platform default.
func executionEnvironmentV1(service *runv1.Service) string {
	if service.Spec == nil || service.Spec.Template == nil || service.Spec.Template.Metadata == nil {
		return ""
	}
	switch service.Spec.Template.Metadata.Annotations["run.googleapis.com/execution-environment"] {
	case "gen1":
		return "gen1"
	case "gen2":
		return "gen2"
	default:
		return ""
	}
}

func serviceURLV1(service *runv1.Service) string {
	if service.Status != nil {
		if service.Status.Url != "" {
			return service.Status.Url
		}
		if service.Status.Address != nil {
			return service.Status.Address.Url
		}
	}
	return ""
}

func runtimeClassNameV1(spec *runv1.RevisionSpec) string {
	if spec == nil {
		return ""
	}
	return spec.RuntimeClassName
}

func containersFromV1(spec *runv1.RevisionSpec) []Container {
	if spec == nil {
		return nil
	}
	result := make([]Container, 0, len(spec.Containers))
	for _, container := range spec.Containers {
		result = append(result, Container{Name: container.Name, Image: container.Image})
	}
	return result
}

func jobFromPB(project, region string, job *runpb.Job) Job {
	return Job{
		Project:              project,
		Region:               region,
		Name:                 path.Base(job.GetName()),
		ExecutionEnvironment: executionEnvironmentFromPB(job.GetTemplate().GetTemplate().GetExecutionEnvironment()),
		Labels:               copyStringMap(job.GetLabels()),
		Annotations:          copyStringMap(job.GetAnnotations()),
		Containers:           containersFromPB(job.GetTemplate().GetTemplate().GetContainers()),
	}
}

func containersFromPB(containers []*runpb.Container) []Container {
	result := make([]Container, 0, len(containers))
	for _, container := range containers {
		result = append(result, Container{Name: container.GetName(), Image: container.GetImage()})
	}
	return result
}

func ingressFromPB(ingress runpb.IngressTraffic) string {
	name := strings.TrimPrefix(ingress.String(), "INGRESS_TRAFFIC_")
	switch name {
	case "ALL":
		return "all"
	case "INTERNAL_ONLY":
		return "internal"
	case "INTERNAL_LOAD_BALANCER":
		return "internal-and-cloud-load-balancing"
	default:
		return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	}
}

func ingressFromAnnotation(ingress string) string {
	if ingress == "" {
		return "all"
	}
	if ingress == "internal-and-cloud-load-balancing" {
		return ingress
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(ingress, "INGRESS_TRAFFIC_"), "_", "-"))
}

func parseBoolAnnotation(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "true")
}

func backendServiceURLsFromURLMap(urlMap *computepb.UrlMap) []string {
	seen := map[string]struct{}{}
	var urls []string
	add := func(url string) {
		if url == "" {
			return
		}
		if _, ok := seen[url]; ok {
			return
		}
		seen[url] = struct{}{}
		urls = append(urls, url)
	}
	add(urlMap.GetDefaultService())
	for _, matcher := range urlMap.GetPathMatchers() {
		add(matcher.GetDefaultService())
		for _, rule := range matcher.GetPathRules() {
			add(rule.GetService())
		}
		for _, rule := range matcher.GetRouteRules() {
			add(rule.GetService())
			if action := rule.GetRouteAction(); action != nil {
				for _, weighted := range action.GetWeightedBackendServices() {
					add(weighted.GetBackendService())
				}
			}
		}
	}
	return urls
}

func routeMetadataByBackendURLFromURLMap(urlMap *computepb.UrlMap) map[string]LoadBalancerRoute {
	result := map[string]LoadBalancerRoute{}
	matcherHosts := map[string][]string{}
	for _, hostRule := range urlMap.GetHostRules() {
		matcherHosts[hostRule.GetPathMatcher()] = append(matcherHosts[hostRule.GetPathMatcher()], hostRule.GetHosts()...)
	}
	add := func(backendURL string, metadata LoadBalancerRoute) {
		if backendURL == "" {
			return
		}
		existing := result[backendURL]
		existing.Hostnames = appendStringSet(existing.Hostnames, metadata.Hostnames...)
		existing.Paths = append(existing.Paths, metadata.Paths...)
		existing.Headers = append(existing.Headers, metadata.Headers...)
		existing.PathRedirects = append(existing.PathRedirects, metadata.PathRedirects...)
		if existing.BackendReference == "" {
			existing.BackendReference = path.Base(backendURL)
		}
		result[backendURL] = existing
	}
	add(urlMap.GetDefaultService(), LoadBalancerRoute{})
	for _, matcher := range urlMap.GetPathMatchers() {
		base := LoadBalancerRoute{Hostnames: append([]string(nil), matcherHosts[matcher.GetName()]...)}
		add(matcher.GetDefaultService(), base)
		for _, rule := range matcher.GetPathRules() {
			metadata := base
			for _, pathValue := range rule.GetPaths() {
				metadata.Paths = append(metadata.Paths, RoutePath{Type: "PathRule", Value: pathValue})
			}
			if rewrite := routeActionRewrite(rule.GetRouteAction()); len(rewrite) > 0 {
				metadata.PathRedirects = append(metadata.PathRedirects, rewrite...)
			}
			add(rule.GetService(), metadata)
		}
		for _, rule := range matcher.GetRouteRules() {
			metadata := base
			metadata.Paths = append(metadata.Paths, routeRulePaths(rule)...)
			metadata.Headers = append(metadata.Headers, routeRuleHeaders(rule)...)
			if rewrite := routeActionRewrite(rule.GetRouteAction()); len(rewrite) > 0 {
				metadata.PathRedirects = append(metadata.PathRedirects, rewrite...)
			}
			add(rule.GetService(), metadata)
			if action := rule.GetRouteAction(); action != nil {
				for _, weighted := range action.GetWeightedBackendServices() {
					add(weighted.GetBackendService(), metadata)
				}
			}
		}
	}
	return result
}

func routeRulePaths(rule *computepb.HttpRouteRule) []RoutePath {
	var paths []RoutePath
	for _, match := range rule.GetMatchRules() {
		switch {
		case match.GetPrefixMatch() != "":
			paths = append(paths, RoutePath{Type: "PrefixMatch", Value: match.GetPrefixMatch()})
		case match.GetFullPathMatch() != "":
			paths = append(paths, RoutePath{Type: "FullPathMatch", Value: match.GetFullPathMatch()})
		case match.GetRegexMatch() != "":
			paths = append(paths, RoutePath{Type: "RegexMatch", Value: match.GetRegexMatch()})
		case match.GetPathTemplateMatch() != "":
			paths = append(paths, RoutePath{Type: "PathTemplateMatch", Value: match.GetPathTemplateMatch()})
		}
	}
	return paths
}

func routeRuleHeaders(rule *computepb.HttpRouteRule) []RouteHeader {
	var headers []RouteHeader
	for _, match := range rule.GetMatchRules() {
		for _, header := range match.GetHeaderMatches() {
			if header.GetHeaderName() == "" {
				continue
			}
			headers = append(headers, routeHeaderMatch(header))
		}
	}
	return headers
}

func routeHeaderMatch(header *computepb.HttpHeaderMatch) RouteHeader {
	result := RouteHeader{Name: header.GetHeaderName()}
	switch {
	case header.GetExactMatch() != "":
		result.Type = "ExactMatch"
		result.Value = header.GetExactMatch()
	case header.GetPrefixMatch() != "":
		result.Type = "PrefixMatch"
		result.Value = header.GetPrefixMatch()
	case header.GetSuffixMatch() != "":
		result.Type = "SuffixMatch"
		result.Value = header.GetSuffixMatch()
	case header.GetRegexMatch() != "":
		result.Type = "RegexMatch"
		result.Value = header.GetRegexMatch()
	case header.GetPresentMatch():
		result.Type = "PresentMatch"
	}
	if header.GetInvertMatch() {
		result.Type = "Not" + result.Type
	}
	return result
}

func routeActionRewrite(action *computepb.HttpRouteAction) []RouteRewrite {
	if action == nil || action.GetUrlRewrite() == nil {
		return nil
	}
	urlRewrite := action.GetUrlRewrite()
	rewrite := RouteRewrite{
		HostnameReplace:        urlRewrite.GetHostRewrite(),
		PathReplacePrefixMatch: urlRewrite.GetPathPrefixRewrite(),
	}
	if rewrite.HostnameReplace == "" && rewrite.PathReplacePrefixMatch == "" {
		return nil
	}
	return []RouteRewrite{rewrite}
}

func appendStringSet(values []string, additions ...string) []string {
	for _, addition := range additions {
		found := false
		for _, value := range values {
			if value == addition {
				found = true
				break
			}
		}
		if !found && addition != "" {
			values = append(values, addition)
		}
	}
	return values
}

func cloudRunServiceFromNEG(neg *computepb.NetworkEndpointGroup) (string, string, bool) {
	if neg == nil || neg.GetNetworkEndpointType() != "SERVERLESS" || neg.GetCloudRun() == nil {
		return "", "", false
	}
	service := neg.GetCloudRun().GetService()
	if service == "" {
		return "", "", false
	}
	return service, regionFromURL(neg.GetRegion()), true
}

func backendIAPEnabled(backend *computepb.BackendService) bool {
	return backend != nil && backend.GetIap() != nil && backend.GetIap().GetEnabled()
}

func backendSecurityPolicy(backend *computepb.BackendService) string {
	if backend == nil || backend.GetSecurityPolicy() == "" {
		return ""
	}
	return path.Base(backend.GetSecurityPolicy())
}

func regionFromURL(value string) string {
	parts := strings.Split(value, "/")
	for i, part := range parts {
		if part == "regions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
