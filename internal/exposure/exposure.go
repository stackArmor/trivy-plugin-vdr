package exposure

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/matthewvenne/trivy-plugin-vdr/internal/model"
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

	serviceExposures := make([]serviceExposure, 0)
	serviceExposures = append(serviceExposures, analyzeIngresses(objects.Ingresses, serviceIndex, ingressClasses, ingressClassParams, backendConfigs)...)
	serviceExposures = append(serviceExposures, analyzeGatewayRoutes(objects.Unstructured, gateways, awsGatewayPublic, gcpBackendPolicies)...)

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
		provider, public, evidence := classifyIngress(ingress, classes, classParams)
		if !public {
			continue
		}
		for _, serviceName := range ingressServiceNames(ingress) {
			key := serviceKey{namespace: ingress.Namespace, name: serviceName}
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
				if protection, ok := backendConfigProtection(services[key], backendConfigs); ok {
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

func ingressServiceNames(ingress networkingv1.Ingress) []string {
	seen := map[string]struct{}{}
	var names []string
	add := func(backend networkingv1.IngressBackend) {
		if backend.Service == nil || backend.Service.Name == "" {
			return
		}
		if _, ok := seen[backend.Service.Name]; ok {
			return
		}
		seen[backend.Service.Name] = struct{}{}
		names = append(names, backend.Service.Name)
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
	sort.Strings(names)
	return names
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
		if object.GetKind() != "IngressClassParams" {
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
		if object.GetKind() != "BackendConfig" {
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

func backendConfigProtection(service corev1.Service, configs map[serviceKey]protectionInfo) (protectionInfo, bool) {
	for _, configName := range backendConfigForService(service) {
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
		if object.GetKind() != "GCPBackendPolicy" {
			continue
		}
		enabled, _, _ := unstructured.NestedBool(object.Object, "spec", "default", "iap", "enabled")
		if !enabled {
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
		evidence := fmt.Sprintf("GKE GCPBackendPolicy %s/%s enables IAP for Service %s/%s", object.GetNamespace(), object.GetName(), object.GetNamespace(), serviceName)
		index[serviceKey{namespace: object.GetNamespace(), name: serviceName}] = protectionInfo{
			protection: model.AccessProtection{Type: "iap", Enabled: true, Provider: "gke", Evidence: evidence},
			evidence:   evidence,
		}
	}
	return index
}

func analyzeGatewayRoutes(
	objects []unstructured.Unstructured,
	gateways map[serviceKey]gatewayInfo,
	awsGatewayPublic map[serviceKey]string,
	gcpBackendPolicies map[serviceKey]protectionInfo,
) []serviceExposure {
	exposures := make([]serviceExposure, 0)
	for _, route := range objects {
		routeKind := route.GetKind()
		if !isGatewayRouteKind(routeKind) {
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
						exposure.InternetAccessible = false
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
		if object.GetKind() != "Gateway" {
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
		if object.GetKind() != "LoadBalancerConfiguration" {
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

type objectRef struct {
	namespace string
	name      string
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
			if kind != "" && kind != "Service" {
				continue
			}
			name, _ := backend["name"].(string)
			if name == "" {
				continue
			}
			namespace, _ := backend["namespace"].(string)
			ref := objectRef{namespace: namespace, name: name}
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

func backendConfigForService(service corev1.Service) []string {
	value := service.Annotations["cloud.google.com/backend-config"]
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
	add(parsed.Default)
	for _, name := range parsed.Ports {
		add(name)
	}
	sort.Strings(names)
	return names
}
