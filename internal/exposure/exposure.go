package exposure

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Objects struct {
	Services       []corev1.Service
	Ingresses      []networkingv1.Ingress
	IngressClasses []networkingv1.IngressClass
	Unstructured   []unstructured.Unstructured
}

type serviceExposure struct {
	serviceNamespace string
	serviceName      string
	exposure         model.Exposure
}

type serviceKey struct {
	namespace string
	name      string
}

type ingressServiceRef struct {
	name       string
	portName   string
	portNumber int32
}

type gatewayInfo struct {
	provider string
	public   bool
	evidence string
}

type protectionInfo struct {
	protection model.AccessProtection
	evidence   string
}

// Analyze returns resource/container-level exposure for inventory workloads selected by Services.
func Analyze(inventory *model.Inventory, objects Objects) map[model.ResourceRef]model.Exposure {
	if inventory == nil {
		return map[model.ResourceRef]model.Exposure{}
	}

	serviceIndex := indexServices(objects.Services)
	workloadsByService := selectWorkloadsByService(inventory, serviceIndex)
	gcpBackendPolicies := indexGCPBackendPolicies(objects.Unstructured)
	backendConfigs := indexBackendConfigs(objects.Unstructured)
	ingressClasses := indexIngressClasses(objects.IngressClasses)
	ingressClassParams := indexIngressClassParams(objects.Unstructured)
	gateways := indexGateways(objects.Unstructured)
	awsGatewayPublic := indexAWSGatewayLoadBalancers(objects.Unstructured)
	referenceGrants := indexReferenceGrants(objects.Unstructured)

	serviceExposures := make([]serviceExposure, 0)
	serviceExposures = append(serviceExposures, analyzeIngresses(objects.Ingresses, serviceIndex, ingressClasses, ingressClassParams, backendConfigs)...)
	serviceExposures = append(serviceExposures, analyzeGatewayRoutes(objects.Unstructured, gateways, awsGatewayPublic, gcpBackendPolicies, referenceGrants)...)
	serviceExposures = append(serviceExposures, analyzeServiceExposure(objects.Services)...)

	result := map[model.ResourceRef]model.Exposure{}
	for _, item := range serviceExposures {
		key := serviceKey{namespace: item.serviceNamespace, name: item.serviceName}
		for _, workload := range workloadsByService[key] {
			applyWorkloadExposure(result, workload, item.exposure)
		}
	}
	return result
}

func indexServices(services []corev1.Service) map[serviceKey]corev1.Service {
	index := make(map[serviceKey]corev1.Service, len(services))
	for _, service := range services {
		index[serviceKey{namespace: service.Namespace, name: service.Name}] = service
	}
	return index
}

func selectWorkloadsByService(inventory *model.Inventory, services map[serviceKey]corev1.Service) map[serviceKey][]model.ResourceInventory {
	selected := map[serviceKey][]model.ResourceInventory{}
	for key, service := range services {
		if len(service.Spec.Selector) == 0 {
			continue
		}
		for _, resource := range inventory.Resources {
			if resource.Resource.Namespace != key.namespace {
				continue
			}
			if labelsMatchSelector(resource.Labels, service.Spec.Selector) {
				selected[key] = append(selected[key], resource)
			}
		}
		sort.Slice(selected[key], func(i, j int) bool {
			return resourceSortKey(selected[key][i].Resource) < resourceSortKey(selected[key][j].Resource)
		})
	}
	return selected
}

func labelsMatchSelector(labels, selector map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func analyzeIngresses(
	ingresses []networkingv1.Ingress,
	services map[serviceKey]corev1.Service,
	classes map[string]networkingv1.IngressClass,
	classParams map[string]string,
	backendConfigs map[serviceKey]protectionInfo,
) []serviceExposure {
	exposures := make([]serviceExposure, 0)
	for _, ingress := range ingresses {
		// An ingress with no provisioned load balancer is not actually serving
		// traffic, so it does not expose anything. Skipping it also means that
		// when a Gateway and an unprovisioned Ingress both target a service, the
		// Gateway's exposure is the one that applies.
		if !ingressHasLoadBalancer(ingress) {
			continue
		}
		provider, public, evidence := classifyIngress(ingress, classes, classParams)
		if !public {
			continue
		}
		for _, serviceRef := range ingressServiceRefs(ingress) {
			key := serviceKey{namespace: ingress.Namespace, name: serviceRef.name}
			if _, ok := services[key]; !ok {
				continue
			}
			exposure := model.Exposure{
				InternetAccessible: true,
				Provider:           provider,
				RouteKind:          "Ingress",
				RouteName:          ingress.Name,
				Evidence:           []string{evidence},
			}
			if provider == "gke" {
				if protection, ok := backendConfigProtection(services[key], serviceRef, backendConfigs); ok {
					exposure.InternetAccessible = false
					exposure.Protection = copyProtection(protection.protection)
					exposure.Evidence = append(exposure.Evidence, protection.evidence)
				}
			}
			if provider == "aws" {
				if protection, ok := awsALBProtection(ingress); ok {
					exposure.InternetAccessible = false
					exposure.Protection = &protection.protection
					exposure.Evidence = append(exposure.Evidence, protection.evidence)
				}
			}
			exposures = append(exposures, serviceExposure{serviceNamespace: key.namespace, serviceName: key.name, exposure: exposure})
		}
	}
	return exposures
}

// ingressHasLoadBalancer reports whether the ingress has a load balancer address
// assigned in its status (an IP or hostname), i.e. it is actually provisioned.
func ingressHasLoadBalancer(ingress networkingv1.Ingress) bool {
	for _, lb := range ingress.Status.LoadBalancer.Ingress {
		if lb.IP != "" || lb.Hostname != "" {
			return true
		}
	}
	return false
}

func classifyIngress(ingress networkingv1.Ingress, classes map[string]networkingv1.IngressClass, classParams map[string]string) (string, bool, string) {
	className := ingressClassName(ingress)
	switch className {
	case "gce":
		return "gke", true, fmt.Sprintf("GKE Ingress %s/%s uses public class gce", ingress.Namespace, ingress.Name)
	case "gce-internal":
		return "gke", false, ""
	case "alb":
		if strings.EqualFold(ingress.Annotations["alb.ingress.kubernetes.io/scheme"], "internet-facing") {
			return "aws", true, fmt.Sprintf("AWS ALB Ingress %s/%s uses internet-facing scheme", ingress.Namespace, ingress.Name)
		}
		if class, ok := classes[className]; ok {
			if class.Spec.Controller != "ingress.k8s.aws/alb" {
				return "", false, ""
			}
			paramsName := ingressClassParamsName(class)
			if strings.EqualFold(classParams[paramsName], "internet-facing") {
				return "aws", true, fmt.Sprintf("AWS ALB IngressClassParams %s uses internet-facing scheme", paramsName)
			}
		}
		return "aws", false, ""
	default:
		return "", false, ""
	}
}

func ingressClassName(ingress networkingv1.Ingress) string {
	if ingress.Spec.IngressClassName != nil {
		return *ingress.Spec.IngressClassName
	}
	return ingress.Annotations["kubernetes.io/ingress.class"]
}

func ingressClassParamsName(class networkingv1.IngressClass) string {
	if class.Spec.Parameters == nil {
		return ""
	}
	return class.Spec.Parameters.Name
}

func ingressServiceRefs(ingress networkingv1.Ingress) []ingressServiceRef {
	seen := map[ingressServiceRef]struct{}{}
	var refs []ingressServiceRef
	add := func(backend networkingv1.IngressBackend) {
		if backend.Service == nil || backend.Service.Name == "" {
			return
		}
		ref := ingressServiceRef{
			name:       backend.Service.Name,
			portName:   backend.Service.Port.Name,
			portNumber: backend.Service.Port.Number,
		}
		if _, ok := seen[ref]; ok {
			return
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	if ingress.Spec.DefaultBackend != nil {
		add(*ingress.Spec.DefaultBackend)
	}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			add(path.Backend)
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].name != refs[j].name {
			return refs[i].name < refs[j].name
		}
		if refs[i].portName != refs[j].portName {
			return refs[i].portName < refs[j].portName
		}
		return refs[i].portNumber < refs[j].portNumber
	})
	return refs
}

func indexIngressClasses(classes []networkingv1.IngressClass) map[string]networkingv1.IngressClass {
	index := make(map[string]networkingv1.IngressClass, len(classes))
	for _, class := range classes {
		index[class.Name] = class
	}
	return index
}

func indexIngressClassParams(objects []unstructured.Unstructured) map[string]string {
	index := map[string]string{}
	for _, object := range objects {
		if !hasGroupKind(object, "elbv2.k8s.aws", "IngressClassParams") {
			continue
		}
		scheme, _, _ := unstructured.NestedString(object.Object, "spec", "scheme")
		if scheme != "" {
			index[object.GetName()] = scheme
		}
	}
	return index
}

func awsALBProtection(ingress networkingv1.Ingress) (protectionInfo, bool) {
	authType := strings.ToLower(ingress.Annotations["alb.ingress.kubernetes.io/auth-type"])
	if authType != "oidc" && authType != "cognito" {
		return protectionInfo{}, false
	}
	unauthenticatedAction := strings.ToLower(ingress.Annotations["alb.ingress.kubernetes.io/auth-on-unauthenticated-request"])
	if unauthenticatedAction != "" && unauthenticatedAction != "authenticate" && unauthenticatedAction != "deny" {
		return protectionInfo{}, false
	}
	evidence := fmt.Sprintf("AWS ALB Ingress %s/%s uses %s authentication", ingress.Namespace, ingress.Name, authType)
	return protectionInfo{
		protection: model.AccessProtection{
			Type:     authType,
			Enabled:  true,
			Provider: "aws",
			Evidence: evidence,
		},
		evidence: evidence,
	}, true
}

func indexBackendConfigs(objects []unstructured.Unstructured) map[serviceKey]protectionInfo {
	configs := map[serviceKey]protectionInfo{}
	for _, object := range objects {
		if !hasGroupKind(object, "cloud.google.com", "BackendConfig") {
			continue
		}
		enabled, _, _ := unstructured.NestedBool(object.Object, "spec", "iap", "enabled")
		if !enabled {
			continue
		}
		evidence := fmt.Sprintf("GKE BackendConfig %s/%s enables IAP", object.GetNamespace(), object.GetName())
		configs[serviceKey{namespace: object.GetNamespace(), name: object.GetName()}] = protectionInfo{
			protection: model.AccessProtection{Type: "iap", Enabled: true, Provider: "gke", Evidence: evidence},
			evidence:   evidence,
		}
	}
	return configs
}

func backendConfigProtection(service corev1.Service, ref ingressServiceRef, configs map[serviceKey]protectionInfo) (protectionInfo, bool) {
	for _, configName := range backendConfigForServicePort(service, ref) {
		configKey := serviceKey{namespace: service.Namespace, name: configName}
		protection, ok := configs[configKey]
		if !ok {
			continue
		}
		evidence := fmt.Sprintf("GKE BackendConfig %s/%s enables IAP for Service %s/%s", service.Namespace, configName, service.Namespace, service.Name)
		protection.protection.Evidence = evidence
		protection.evidence = evidence
		return protection, true
	}
	return protectionInfo{}, false
}

func indexGCPBackendPolicies(objects []unstructured.Unstructured) map[serviceKey]protectionInfo {
	index := map[serviceKey]protectionInfo{}
	for _, object := range objects {
		if !hasGroupKind(object, "networking.gke.io", "GCPBackendPolicy") {
			continue
		}
		targetKind, _, _ := unstructured.NestedString(object.Object, "spec", "targetRef", "kind")
		if targetKind != "" && targetKind != "Service" {
			continue
		}
		serviceName, _, _ := unstructured.NestedString(object.Object, "spec", "targetRef", "name")
		if serviceName == "" {
			continue
		}
		enabled, _, _ := unstructured.NestedBool(object.Object, "spec", "default", "iap", "enabled")
		cloudArmorPolicy := gcpBackendPolicyCloudArmorPolicy(object)
		if !enabled && cloudArmorPolicy == "" {
			continue
		}
		protection := model.AccessProtection{Provider: "gke"}
		var evidence string
		if enabled {
			evidence = fmt.Sprintf("GKE GCPBackendPolicy %s/%s enables IAP for Service %s/%s", object.GetNamespace(), object.GetName(), object.GetNamespace(), serviceName)
			protection.Type = "iap"
			protection.Enabled = true
			protection.Evidence = evidence
		}
		if cloudArmorPolicy != "" {
			armorEvidence := fmt.Sprintf("GKE GCPBackendPolicy %s/%s attaches Cloud Armor policy %s to Service %s/%s", object.GetNamespace(), object.GetName(), cloudArmorPolicy, object.GetNamespace(), serviceName)
			protection.SecurityPolicy = &model.SecurityPolicy{
				Type:     "cloud-armor",
				Name:     cloudArmorPolicy,
				Provider: "gke",
				Evidence: armorEvidence,
			}
			if evidence == "" {
				evidence = armorEvidence
			} else {
				evidence += "; " + armorEvidence
			}
		}
		index[serviceKey{namespace: object.GetNamespace(), name: serviceName}] = protectionInfo{
			protection: protection,
			evidence:   evidence,
		}
	}
	return index
}

func gcpBackendPolicyCloudArmorPolicy(object unstructured.Unstructured) string {
	if policy, ok, _ := unstructured.NestedString(object.Object, "spec", "default", "securityPolicy"); ok {
		return policy
	}
	if policy, ok, _ := unstructured.NestedString(object.Object, "spec", "default", "securityPolicy", "name"); ok {
		return policy
	}
	return ""
}

func analyzeGatewayRoutes(
	objects []unstructured.Unstructured,
	gateways map[serviceKey]gatewayInfo,
	awsGatewayPublic map[serviceKey]string,
	gcpBackendPolicies map[serviceKey]protectionInfo,
	referenceGrants map[string][]referenceGrantInfo,
) []serviceExposure {
	exposures := make([]serviceExposure, 0)
	for _, route := range objects {
		routeKind := route.GetKind()
		if !hasAPIGroup(route, "gateway.networking.k8s.io") || !isGatewayRouteKind(routeKind) {
			continue
		}
		for _, parent := range routeParentRefs(route) {
			parentNamespace := parent.namespace
			if parentNamespace == "" {
				parentNamespace = route.GetNamespace()
			}
			gatewayKey := serviceKey{namespace: parentNamespace, name: parent.name}
			gateway, ok := gateways[gatewayKey]
			if !ok {
				continue
			}
			public := gateway.public
			evidence := gateway.evidence
			if awsEvidence, ok := awsGatewayPublic[gatewayKey]; ok {
				public = true
				evidence = awsEvidence
				gateway.provider = "aws"
			}
			if !public {
				continue
			}
			for _, backend := range routeBackendRefs(route) {
				serviceNamespace := backend.namespace
				if serviceNamespace == "" {
					serviceNamespace = route.GetNamespace()
				}
				if serviceNamespace != route.GetNamespace() && !referenceGrantAllows(referenceGrants[serviceNamespace], route, backend) {
					continue
				}
				key := serviceKey{namespace: serviceNamespace, name: backend.name}
				exposure := model.Exposure{
					InternetAccessible: true,
					Provider:           gateway.provider,
					RouteKind:          routeKind,
					RouteName:          route.GetName(),
					Evidence:           []string{evidence},
				}
				if gateway.provider == "gke" {
					if protection, ok := gcpBackendPolicies[key]; ok {
						if protection.protection.Enabled {
							exposure.InternetAccessible = false
						}
						exposure.Protection = copyProtection(protection.protection)
						exposure.Evidence = append(exposure.Evidence, protection.evidence)
					}
				}
				exposures = append(exposures, serviceExposure{serviceNamespace: key.namespace, serviceName: key.name, exposure: exposure})
			}
		}
	}
	return exposures
}

func indexGateways(objects []unstructured.Unstructured) map[serviceKey]gatewayInfo {
	index := map[serviceKey]gatewayInfo{}
	for _, object := range objects {
		if !hasGroupKind(object, "gateway.networking.k8s.io", "Gateway") {
			continue
		}
		className, _, _ := unstructured.NestedString(object.Object, "spec", "gatewayClassName")
		provider, public := classifyGatewayClass(className)
		evidence := ""
		if public && provider == "gke" {
			evidence = fmt.Sprintf("GKE Gateway %s/%s uses public class %s", object.GetNamespace(), object.GetName(), className)
		}
		index[serviceKey{namespace: object.GetNamespace(), name: object.GetName()}] = gatewayInfo{
			provider: provider,
			public:   public,
			evidence: evidence,
		}
	}
	return index
}

func classifyGatewayClass(className string) (string, bool) {
	switch className {
	case "gke-l7-global-external-managed", "gke-l7-regional-external-managed", "gke-l7-gxlb", "gke-l7-gxlb-mc":
		return "gke", true
	case "gke-l7-rilb", "gke-l7-rilb-mc":
		return "gke", false
	default:
		return "", false
	}
}

func indexAWSGatewayLoadBalancers(objects []unstructured.Unstructured) map[serviceKey]string {
	index := map[serviceKey]string{}
	for _, object := range objects {
		if !hasGroupKind(object, "gateway.k8s.aws", "LoadBalancerConfiguration") {
			continue
		}
		scheme, _, _ := unstructured.NestedString(object.Object, "spec", "scheme")
		if !strings.EqualFold(scheme, "internet-facing") {
			continue
		}
		gatewayName, _, _ := unstructured.NestedString(object.Object, "spec", "targetRef", "name")
		if gatewayName == "" {
			gatewayName = object.GetName()
		}
		evidence := fmt.Sprintf("AWS Gateway %s/%s LoadBalancerConfiguration scheme is internet-facing", object.GetNamespace(), gatewayName)
		index[serviceKey{namespace: object.GetNamespace(), name: gatewayName}] = evidence
	}
	return index
}

func isGatewayRouteKind(kind string) bool {
	switch kind {
	case "HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute":
		return true
	default:
		return false
	}
}

func indexReferenceGrants(objects []unstructured.Unstructured) map[string][]referenceGrantInfo {
	index := map[string][]referenceGrantInfo{}
	for _, object := range objects {
		if !hasGroupKind(object, "gateway.networking.k8s.io", "ReferenceGrant") {
			continue
		}
		grant := referenceGrantInfo{
			from: referenceGrantFromRefs(object),
			to:   referenceGrantToRefs(object),
		}
		if len(grant.from) == 0 || len(grant.to) == 0 {
			continue
		}
		index[object.GetNamespace()] = append(index[object.GetNamespace()], grant)
	}
	return index
}

func referenceGrantFromRefs(object unstructured.Unstructured) []referenceGrantFrom {
	items, _, _ := unstructured.NestedSlice(object.Object, "spec", "from")
	refs := make([]referenceGrantFrom, 0, len(items))
	for _, item := range items {
		ref, ok := item.(map[string]any)
		if !ok {
			continue
		}
		group, _ := ref["group"].(string)
		kind, _ := ref["kind"].(string)
		namespace, _ := ref["namespace"].(string)
		if group == "" || kind == "" || namespace == "" {
			continue
		}
		refs = append(refs, referenceGrantFrom{group: group, kind: kind, namespace: namespace})
	}
	return refs
}

func referenceGrantToRefs(object unstructured.Unstructured) []referenceGrantTo {
	items, _, _ := unstructured.NestedSlice(object.Object, "spec", "to")
	refs := make([]referenceGrantTo, 0, len(items))
	for _, item := range items {
		ref, ok := item.(map[string]any)
		if !ok {
			continue
		}
		group, _ := ref["group"].(string)
		kind, _ := ref["kind"].(string)
		name, _ := ref["name"].(string)
		if kind == "" {
			continue
		}
		refs = append(refs, referenceGrantTo{group: group, kind: kind, name: name})
	}
	return refs
}

func referenceGrantAllows(grants []referenceGrantInfo, route unstructured.Unstructured, backend objectRef) bool {
	for _, grant := range grants {
		if !referenceGrantAllowsFrom(grant, route) {
			continue
		}
		if referenceGrantAllowsTo(grant, backend) {
			return true
		}
	}
	return false
}

func referenceGrantAllowsFrom(grant referenceGrantInfo, route unstructured.Unstructured) bool {
	routeGroup := apiGroup(route.GetAPIVersion())
	for _, from := range grant.from {
		if from.group == routeGroup && from.kind == route.GetKind() && from.namespace == route.GetNamespace() {
			return true
		}
	}
	return false
}

func referenceGrantAllowsTo(grant referenceGrantInfo, backend objectRef) bool {
	for _, to := range grant.to {
		if to.group != backend.group || to.kind != backend.kind {
			continue
		}
		if to.name == "" || to.name == backend.name {
			return true
		}
	}
	return false
}

type objectRef struct {
	namespace string
	name      string
	group     string
	kind      string
}

type referenceGrantInfo struct {
	from []referenceGrantFrom
	to   []referenceGrantTo
}

type referenceGrantFrom struct {
	group     string
	kind      string
	namespace string
}

type referenceGrantTo struct {
	group string
	kind  string
	name  string
}

func routeParentRefs(route unstructured.Unstructured) []objectRef {
	refs, _, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
	result := make([]objectRef, 0, len(refs))
	for _, item := range refs {
		ref, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := ref["name"].(string)
		if name == "" {
			continue
		}
		namespace, _ := ref["namespace"].(string)
		result = append(result, objectRef{namespace: namespace, name: name})
	}
	return result
}

func routeBackendRefs(route unstructured.Unstructured) []objectRef {
	seen := map[objectRef]struct{}{}
	var result []objectRef
	rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
	for _, ruleItem := range rules {
		rule, ok := ruleItem.(map[string]any)
		if !ok {
			continue
		}
		backendRefs, _ := rule["backendRefs"].([]any)
		for _, backendItem := range backendRefs {
			backend, ok := backendItem.(map[string]any)
			if !ok {
				continue
			}
			kind, _ := backend["kind"].(string)
			if kind == "" {
				kind = "Service"
			}
			group, _ := backend["group"].(string)
			if group != "" || kind != "Service" {
				continue
			}
			name, _ := backend["name"].(string)
			if name == "" {
				continue
			}
			namespace, _ := backend["namespace"].(string)
			ref := objectRef{namespace: namespace, name: name, group: group, kind: kind}
			if _, ok := seen[ref]; ok {
				continue
			}
			seen[ref] = struct{}{}
			result = append(result, ref)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].namespace != result[j].namespace {
			return result[i].namespace < result[j].namespace
		}
		return result[i].name < result[j].name
	})
	return result
}

func applyWorkloadExposure(result map[model.ResourceRef]model.Exposure, resource model.ResourceInventory, exposure model.Exposure) {
	for _, image := range resource.Images {
		ref := resource.Resource
		ref.ContainerName = image.Name
		ref.ContainerType = image.ContainerType
		ref.RestartPolicy = image.RestartPolicy

		containerExposure := cloneExposure(exposure)
		switch {
		case image.ContainerType == "initContainer" && image.RestartPolicy != "Always":
			containerExposure.InternetAccessible = false
			containerExposure.Evidence = append(containerExposure.Evidence,
				fmt.Sprintf("init container %s/%s/%s is not internet accessible because restartPolicy is not Always", resource.Resource.Namespace, resource.Resource.Name, image.Name))
		case image.ContainerType == "initContainer" && image.RestartPolicy == "Always":
			containerExposure.Evidence = append(containerExposure.Evidence,
				fmt.Sprintf("sidecar init container %s/%s/%s inherits exposure because restartPolicy is Always", resource.Resource.Namespace, resource.Resource.Name, image.Name))
		}
		mergeExposure(result, ref, containerExposure)
	}
}

// analyzeServiceExposure marks workloads fronted directly by an externally-scoped
// Service. A type=LoadBalancer Service with a provisioned external address and no
// internal-scheme annotation directly exposes the pods it selects -- this is how
// ingress/gateway controller pods (Traefik, ingress-nginx, Envoy gateways) and any
// directly-LB-published app become internet-reachable, independent of any Ingress
// or Gateway resource. A NodePort Service is recorded as an advisory only: it is
// reachable on node IPs, but whether that is internet-reachable depends on the
// nodes having public IPs and permissive firewall/security-group rules, which is
// not determinable from the cluster -- so it is deliberately NOT counted as
// internet-reachable (it does not inflate IRV or the remediation deadline).
func analyzeServiceExposure(services []corev1.Service) []serviceExposure {
	var exposures []serviceExposure
	for _, svc := range services {
		switch svc.Spec.Type {
		case corev1.ServiceTypeLoadBalancer:
			if !serviceHasLoadBalancerAddress(svc) {
				continue // load balancer not provisioned yet
			}
			if internal, _ := serviceInternalLB(svc); internal {
				continue // internal-scheme load balancer is not internet-reachable
			}
			exposures = append(exposures, serviceExposure{
				serviceNamespace: svc.Namespace,
				serviceName:      svc.Name,
				exposure: model.Exposure{
					InternetAccessible: true,
					Provider:           lbProvider(svc),
					RouteKind:          "Service/LoadBalancer",
					RouteName:          svc.Name,
					Evidence: []string{fmt.Sprintf(
						"Service %s/%s is type=LoadBalancer with a provisioned external address (%s); the pods it selects are directly internet-reachable",
						svc.Namespace, svc.Name, serviceLBAddress(svc))},
				},
			})
		case corev1.ServiceTypeNodePort:
			exposures = append(exposures, nodePortExposure(svc))
		}
	}
	return exposures
}

// nodePortReachableLabel lets an operator declare whether a NodePort Service is
// actually internet-reachable (true) or not (false), since the cluster alone can't
// determine it. When absent, the Service is treated as an unverified advisory.
const nodePortReachableLabel = "vdr.fedramp.io/internet-reachable-nodePort"

func nodePortExposure(svc corev1.Service) serviceExposure {
	ports := nodePortList(svc)
	ex := model.Exposure{RouteKind: "Service/NodePort", RouteName: svc.Name}
	if val, ok := svc.Labels[nodePortReachableLabel]; ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(val)); err == nil {
			ex.InternetAccessible = b
			if b {
				ex.Evidence = []string{fmt.Sprintf(
					"Service %s/%s is type=NodePort (%s), explicitly marked internet-reachable by label %s=true.",
					svc.Namespace, svc.Name, ports, nodePortReachableLabel)}
			} else {
				ex.Evidence = []string{fmt.Sprintf(
					"Service %s/%s is type=NodePort (%s), explicitly marked not internet-reachable by label %s=false.",
					svc.Namespace, svc.Name, ports, nodePortReachableLabel)}
			}
			return serviceExposure{serviceNamespace: svc.Namespace, serviceName: svc.Name, exposure: ex}
		}
	}
	// Missing or unparseable label: unverified, not counted as internet-reachable.
	ex.InternetAccessible = false
	ex.Evidence = []string{fmt.Sprintf(
		"Service %s/%s is type=NodePort (%s); node-IP reachability is unverified and is NOT counted as internet-reachable. Set label %s: \"true\" or \"false\" on the Service to classify it (true if the nodes are internet-facing with the node port reachable).",
		svc.Namespace, svc.Name, ports, nodePortReachableLabel)}
	return serviceExposure{serviceNamespace: svc.Namespace, serviceName: svc.Name, exposure: ex}
}

func serviceHasLoadBalancerAddress(svc corev1.Service) bool {
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" || ing.Hostname != "" {
			return true
		}
	}
	return false
}

func serviceLBAddress(svc corev1.Service) string {
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.Hostname != "" {
			return ing.Hostname
		}
		if ing.IP != "" {
			return ing.IP
		}
	}
	return "external"
}

// serviceInternalLB reports whether a type=LoadBalancer Service is scoped to an
// internal (non-internet) load balancer, via the well-known per-cloud annotations.
func serviceInternalLB(svc corev1.Service) (bool, string) {
	get := func(k string) string { return strings.ToLower(strings.TrimSpace(svc.Annotations[k])) }
	switch {
	case get("networking.gke.io/load-balancer-type") == "internal":
		return true, "GKE internal load balancer"
	case get("cloud.google.com/load-balancer-type") == "internal":
		return true, "GKE (legacy) internal load balancer"
	case get("service.beta.kubernetes.io/aws-load-balancer-scheme") == "internal":
		return true, "AWS internal load balancer"
	case get("service.beta.kubernetes.io/aws-load-balancer-internal") == "true",
		get("service.beta.kubernetes.io/aws-load-balancer-internal") == "0.0.0.0/0":
		return true, "AWS (legacy) internal load balancer"
	case get("service.beta.kubernetes.io/azure-load-balancer-internal") == "true":
		return true, "Azure internal load balancer"
	}
	return false, ""
}

func lbProvider(svc corev1.Service) string {
	for k := range svc.Annotations {
		switch {
		case strings.Contains(k, "aws-load-balancer"):
			return "aws"
		case strings.Contains(k, "gke.io"), strings.Contains(k, "cloud.google.com"):
			return "gcp"
		case strings.Contains(k, "azure-load-balancer"):
			return "azure"
		}
	}
	return ""
}

func nodePortList(svc corev1.Service) string {
	var ports []string
	for _, p := range svc.Spec.Ports {
		if p.NodePort != 0 {
			ports = append(ports, fmt.Sprintf("%d", p.NodePort))
		}
	}
	if len(ports) == 0 {
		return "node ports"
	}
	return "node ports " + strings.Join(ports, ",")
}

func mergeExposure(result map[model.ResourceRef]model.Exposure, ref model.ResourceRef, exposure model.Exposure) {
	existing, ok := result[ref]
	if !ok {
		result[ref] = exposure
		return
	}
	if existing.InternetAccessible {
		return
	}
	if exposure.InternetAccessible {
		result[ref] = exposure
		return
	}
	if existing.Protection == nil && exposure.Protection != nil {
		result[ref] = exposure
	}
}

func cloneExposure(exposure model.Exposure) model.Exposure {
	clone := exposure
	if len(exposure.Evidence) > 0 {
		clone.Evidence = append([]string(nil), exposure.Evidence...)
	}
	if exposure.Protection != nil {
		clone.Protection = copyProtection(*exposure.Protection)
	}
	return clone
}

func copyProtection(protection model.AccessProtection) *model.AccessProtection {
	copied := protection
	return &copied
}

func resourceSortKey(ref model.ResourceRef) string {
	return strings.Join([]string{ref.Namespace, ref.Kind, ref.Name}, "\x00")
}

type backendConfigAnnotation struct {
	Default string            `json:"default"`
	Ports   map[string]string `json:"ports"`
}

func backendConfigForServicePort(service corev1.Service, ref ingressServiceRef) []string {
	value := backendConfigAnnotationValue(service)
	if value == "" {
		return nil
	}
	var parsed backendConfigAnnotation
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var names []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	matchedPort := false
	for portKey, name := range parsed.Ports {
		if servicePortMatchesRef(service, portKey, ref) {
			matchedPort = true
			add(name)
		}
	}
	if !matchedPort {
		add(parsed.Default)
	}
	sort.Strings(names)
	return names
}

func backendConfigAnnotationValue(service corev1.Service) string {
	if value := service.Annotations["cloud.google.com/backend-config"]; value != "" {
		return value
	}
	return service.Annotations["beta.cloud.google.com/backend-config"]
}

func servicePortMatchesRef(service corev1.Service, portKey string, ref ingressServiceRef) bool {
	if portKey == "" {
		return false
	}
	for _, port := range service.Spec.Ports {
		if ref.portName != "" && port.Name != ref.portName {
			continue
		}
		if ref.portNumber != 0 && port.Port != ref.portNumber {
			continue
		}
		if portKey == port.Name || portKey == fmt.Sprint(port.Port) {
			return true
		}
	}
	return false
}

func hasGroupKind(object unstructured.Unstructured, group, kind string) bool {
	return object.GetKind() == kind && hasAPIGroup(object, group)
}

func hasAPIGroup(object unstructured.Unstructured, group string) bool {
	return apiGroup(object.GetAPIVersion()) == group
}

func apiGroup(apiVersion string) string {
	group, _, found := strings.Cut(apiVersion, "/")
	if !found {
		return ""
	}
	return group
}
