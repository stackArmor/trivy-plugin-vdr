package exposure

import (
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAnalyzeGKEGatewayPublicAndInternalClasses(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Unstructured: []unstructured.Unstructured{
			gateway("default", "public-gw", "gke-l7-global-external-managed"),
			httpRoute("default", "public-route", "public-gw", "web-svc"),
			gateway("default", "internal-gw", "gke-l7-rilb"),
			httpRoute("default", "internal-route", "internal-gw", "web-svc"),
		},
	}

	got := Analyze(inv, objects)

	ref := resourceRef("default", "web", "app", "container", "")
	exposure := got[ref]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true: %#v", exposure)
	}
	if exposure.Provider != "gke" || exposure.RouteKind != "HTTPRoute" || exposure.RouteName != "public-route" {
		t.Fatalf("unexpected exposure metadata: %#v", exposure)
	}
	requireEvidence(t, exposure, "GKE Gateway default/public-gw uses public class gke-l7-global-external-managed")
}

func TestAnalyzeGKEGatewayInternalClassIsNotPublic(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Unstructured: []unstructured.Unstructured{
			gateway("default", "internal-gw", "gke-l7-rilb"),
			httpRoute("default", "internal-route", "internal-gw", "web-svc"),
		},
	}

	got := Analyze(inv, objects)

	if len(got) != 0 {
		t.Fatalf("Analyze() returned %#v, want no exposure for internal GKE Gateway", got)
	}
}

func TestAnalyzeGKEGatewayIAPBackendPolicyProtectsTargetService(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Unstructured: []unstructured.Unstructured{
			gateway("default", "public-gw", "gke-l7-global-external-managed"),
			httpRoute("default", "public-route", "public-gw", "web-svc"),
			gcpBackendPolicyIAP("default", "web-iap", "web-svc", true),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "app", "container", "")]
	if exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = true, want false: %#v", exposure)
	}
	if exposure.Protection == nil || exposure.Protection.Type != "iap" || exposure.Protection.Provider != "gke" || !exposure.Protection.Enabled {
		t.Fatalf("Protection = %#v, want enabled GKE IAP", exposure.Protection)
	}
	requireEvidence(t, exposure, "GKE GCPBackendPolicy default/web-iap enables IAP for Service default/web-svc")
}

func TestAnalyzeGKEIngressGCEAndInternalClasses(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Ingresses: []networkingv1.Ingress{
			ingress("default", "public-ing", "gce", "web-svc", nil),
			ingress("default", "internal-ing", "gce-internal", "web-svc", nil),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "app", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true: %#v", exposure)
	}
	if exposure.Provider != "gke" || exposure.RouteKind != "Ingress" || exposure.RouteName != "public-ing" {
		t.Fatalf("unexpected exposure metadata: %#v", exposure)
	}
	requireEvidence(t, exposure, "GKE Ingress default/public-ing uses public class gce")
}

func TestAnalyzeGKEIngressInternalClassIsNotPublic(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services:  []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Ingresses: []networkingv1.Ingress{ingress("default", "internal-ing", "gce-internal", "web-svc", nil)},
	}

	got := Analyze(inv, objects)

	if len(got) != 0 {
		t.Fatalf("Analyze() returned %#v, want no exposure for internal GKE Ingress", got)
	}
}

func TestAnalyzeGKEIngressBackendConfigIAPProtectsTargetService(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{serviceWithAnnotations("default", "web-svc", map[string]string{"app": "web"}, map[string]string{
			"cloud.google.com/backend-config": `{"default":"web-backend"}`,
		})},
		Ingresses: []networkingv1.Ingress{ingress("default", "public-ing", "gce", "web-svc", nil)},
		Unstructured: []unstructured.Unstructured{
			backendConfigIAP("default", "web-backend", true),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "app", "container", "")]
	if exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = true, want false: %#v", exposure)
	}
	if exposure.Protection == nil || exposure.Protection.Type != "iap" || exposure.Protection.Provider != "gke" || !exposure.Protection.Enabled {
		t.Fatalf("Protection = %#v, want enabled GKE IAP", exposure.Protection)
	}
	requireEvidence(t, exposure, "GKE BackendConfig default/web-backend enables IAP for Service default/web-svc")
}

func TestAnalyzeGKEIngressBackendConfigPortsOnlyProtectMatchingServicePort(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{
			serviceWithPortsAndAnnotations("default", "web-svc", map[string]string{"app": "web"}, map[string]string{
				"cloud.google.com/backend-config": `{"ports":{"admin":"admin-backend"}}`,
			}, servicePort("public", 80), servicePort("admin", 8080)),
		},
		Ingresses: []networkingv1.Ingress{ingress("default", "public-ing", "gce", "web-svc", nil)},
		Unstructured: []unstructured.Unstructured{
			backendConfigIAP("default", "admin-backend", true),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "app", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true because Ingress targets unprotected service port: %#v", exposure)
	}
	if exposure.Protection != nil {
		t.Fatalf("Protection = %#v, want nil for unprotected service port", exposure.Protection)
	}
}

func TestAnalyzeGKEIngressBackendConfigPortOverrideIgnoresProtectedDefault(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{
			serviceWithPortsAndAnnotations("default", "web-svc", map[string]string{"app": "web"}, map[string]string{
				"cloud.google.com/backend-config": `{"default":"protected-backend","ports":{"public":"public-backend"}}`,
			}, servicePort("public", 80)),
		},
		Ingresses: []networkingv1.Ingress{ingress("default", "public-ing", "gce", "web-svc", nil)},
		Unstructured: []unstructured.Unstructured{
			backendConfigIAP("default", "protected-backend", true),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "app", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true because explicit service port BackendConfig overrides protected default: %#v", exposure)
	}
	if exposure.Protection != nil {
		t.Fatalf("Protection = %#v, want nil because protected default does not apply to explicit service port", exposure.Protection)
	}
}

func TestAnalyzeGKEIngressBetaBackendConfigAnnotationProtectsTargetService(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{serviceWithAnnotations("default", "web-svc", map[string]string{"app": "web"}, map[string]string{
			"beta.cloud.google.com/backend-config": `{"default":"web-backend"}`,
		})},
		Ingresses: []networkingv1.Ingress{ingress("default", "public-ing", "gce", "web-svc", nil)},
		Unstructured: []unstructured.Unstructured{
			backendConfigIAP("default", "web-backend", true),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "app", "container", "")]
	if exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = true, want false because beta BackendConfig annotation enables IAP: %#v", exposure)
	}
	if exposure.Protection == nil || exposure.Protection.Type != "iap" || exposure.Protection.Provider != "gke" || !exposure.Protection.Enabled {
		t.Fatalf("Protection = %#v, want enabled GKE IAP", exposure.Protection)
	}
}

func TestAnalyzeGKEIngressBackendConfigPortNameAnnotationMatchesIngressPortNumber(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{
			serviceWithPortsAndAnnotations("default", "web-svc", map[string]string{"app": "web"}, map[string]string{
				"cloud.google.com/backend-config": `{"ports":{"public":"web-backend"}}`,
			}, servicePort("public", 80)),
		},
		Ingresses: []networkingv1.Ingress{ingress("default", "public-ing", "gce", "web-svc", nil)},
		Unstructured: []unstructured.Unstructured{
			backendConfigIAP("default", "web-backend", true),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "app", "container", "")]
	if exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = true, want false because BackendConfig targets the service port by name: %#v", exposure)
	}
	if exposure.Protection == nil || exposure.Protection.Type != "iap" || exposure.Protection.Provider != "gke" || !exposure.Protection.Enabled {
		t.Fatalf("Protection = %#v, want enabled GKE IAP", exposure.Protection)
	}
}

func TestAnalyzeGKEIngressBackendConfigPortNumberAnnotationMatchesIngressPortName(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services: []corev1.Service{
			serviceWithPortsAndAnnotations("default", "web-svc", map[string]string{"app": "web"}, map[string]string{
				"cloud.google.com/backend-config": `{"ports":{"80":"web-backend"}}`,
			}, servicePort("public", 80)),
		},
		Ingresses: []networkingv1.Ingress{ingressWithServicePortName("default", "public-ing", "gce", "web-svc", "public", nil)},
		Unstructured: []unstructured.Unstructured{
			backendConfigIAP("default", "web-backend", true),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "app", "container", "")]
	if exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = true, want false because BackendConfig targets the service port by number: %#v", exposure)
	}
	if exposure.Protection == nil || exposure.Protection.Type != "iap" || exposure.Protection.Provider != "gke" || !exposure.Protection.Enabled {
		t.Fatalf("Protection = %#v, want enabled GKE IAP", exposure.Protection)
	}
}

func TestAnalyzeAWSALBIngressSchemeAndClassParams(t *testing.T) {
	inv := inventoryWithWorkload("default", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "api-svc", map[string]string{"app": "api"})},
		IngressClasses: []networkingv1.IngressClass{
			ingressClass("alb", "ingress.k8s.aws/alb", "internet-facing-params"),
		},
		Ingresses: []networkingv1.Ingress{
			ingress("default", "annotation-alb", "alb", "api-svc", map[string]string{
				"alb.ingress.kubernetes.io/scheme": "internet-facing",
			}),
			ingress("default", "params-alb", "alb", "api-svc", nil),
		},
		Unstructured: []unstructured.Unstructured{
			ingressClassParams("internet-facing-params", "internet-facing"),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "api", "api", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true: %#v", exposure)
	}
	if exposure.Provider != "aws" || exposure.RouteKind != "Ingress" {
		t.Fatalf("unexpected exposure metadata: %#v", exposure)
	}
	requireEvidence(t, exposure, "AWS ALB Ingress default/annotation-alb uses internet-facing scheme")
}

func TestAnalyzeAWSALBIngressClassParamsInternetFacing(t *testing.T) {
	inv := inventoryWithWorkload("default", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "api-svc", map[string]string{"app": "api"})},
		IngressClasses: []networkingv1.IngressClass{
			ingressClass("alb", "ingress.k8s.aws/alb", "internet-facing-params"),
		},
		Ingresses: []networkingv1.Ingress{ingress("default", "params-alb", "alb", "api-svc", nil)},
		Unstructured: []unstructured.Unstructured{
			ingressClassParams("internet-facing-params", "internet-facing"),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "api", "api", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true: %#v", exposure)
	}
	if exposure.Provider != "aws" || exposure.RouteKind != "Ingress" || exposure.RouteName != "params-alb" {
		t.Fatalf("unexpected exposure metadata: %#v", exposure)
	}
	requireEvidence(t, exposure, "AWS ALB IngressClassParams internet-facing-params uses internet-facing scheme")
}

func TestAnalyzeAWSALBAuthAnnotationsProtectOIDCAndCognito(t *testing.T) {
	for _, authType := range []string{"oidc", "cognito"} {
		t.Run(authType, func(t *testing.T) {
			inv := inventoryWithWorkload("default", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
			objects := Objects{
				Services: []corev1.Service{service("default", "api-svc", map[string]string{"app": "api"})},
				Ingresses: []networkingv1.Ingress{ingress("default", "auth-alb", "", "api-svc", map[string]string{
					"kubernetes.io/ingress.class":                               "alb",
					"alb.ingress.kubernetes.io/scheme":                          "internet-facing",
					"alb.ingress.kubernetes.io/auth-type":                       authType,
					"alb.ingress.kubernetes.io/auth-on-unauthenticated-request": "authenticate",
				})},
			}

			got := Analyze(inv, objects)

			exposure := got[resourceRef("default", "api", "api", "container", "")]
			if exposure.InternetAccessible {
				t.Fatalf("InternetAccessible = true, want false: %#v", exposure)
			}
			if exposure.Protection == nil || exposure.Protection.Type != authType || exposure.Protection.Provider != "aws" || !exposure.Protection.Enabled {
				t.Fatalf("Protection = %#v, want enabled AWS %s auth", exposure.Protection, authType)
			}
			requireEvidence(t, exposure, "AWS ALB Ingress default/auth-alb uses "+authType+" authentication")
		})
	}
}

func TestAnalyzeAWSALBAuthAllowUnauthenticatedRemainsInternetAccessible(t *testing.T) {
	inv := inventoryWithWorkload("default", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "api-svc", map[string]string{"app": "api"})},
		Ingresses: []networkingv1.Ingress{ingress("default", "auth-alb", "", "api-svc", map[string]string{
			"kubernetes.io/ingress.class":                               "alb",
			"alb.ingress.kubernetes.io/scheme":                          "internet-facing",
			"alb.ingress.kubernetes.io/auth-type":                       "oidc",
			"alb.ingress.kubernetes.io/auth-on-unauthenticated-request": "allow",
		})},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "api", "api", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true when unauthenticated action is allow: %#v", exposure)
	}
	if exposure.Protection != nil {
		t.Fatalf("Protection = %#v, want nil when unauthenticated action is allow", exposure.Protection)
	}
}

func TestAnalyzeAWSGatewayLoadBalancerConfigurationInternetFacing(t *testing.T) {
	inv := inventoryWithWorkload("default", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "api-svc", map[string]string{"app": "api"})},
		Unstructured: []unstructured.Unstructured{
			gateway("default", "aws-gw", "amazon-vpc-lattice"),
			httpRoute("default", "aws-route", "aws-gw", "api-svc"),
			loadBalancerConfiguration("default", "aws-gw", "internet-facing"),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "api", "api", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true: %#v", exposure)
	}
	if exposure.Provider != "aws" || exposure.RouteKind != "HTTPRoute" || exposure.RouteName != "aws-route" {
		t.Fatalf("unexpected exposure metadata: %#v", exposure)
	}
	requireEvidence(t, exposure, "AWS Gateway default/aws-gw LoadBalancerConfiguration scheme is internet-facing")
}

func TestAnalyzeGatewayRouteIgnoresCrossNamespaceBackendRefWithoutReferenceGrant(t *testing.T) {
	inv := inventoryWithWorkload("backend", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
	objects := Objects{
		Services: []corev1.Service{service("backend", "api-svc", map[string]string{"app": "api"})},
		Unstructured: []unstructured.Unstructured{
			gateway("frontend", "public-gw", "gke-l7-global-external-managed"),
			routeWithBackendRef("HTTPRoute", "frontend", "route", "public-gw", map[string]any{
				"name":      "api-svc",
				"namespace": "backend",
				"port":      int64(80),
			}),
		},
	}

	got := Analyze(inv, objects)

	if len(got) != 0 {
		t.Fatalf("Analyze() returned %#v, want no exposure without ReferenceGrant", got)
	}
}

func TestAnalyzeGatewayRouteAllowsCrossNamespaceBackendRefWithReferenceGrant(t *testing.T) {
	inv := inventoryWithWorkload("backend", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
	objects := Objects{
		Services: []corev1.Service{service("backend", "api-svc", map[string]string{"app": "api"})},
		Unstructured: []unstructured.Unstructured{
			gateway("frontend", "public-gw", "gke-l7-global-external-managed"),
			routeWithBackendRef("HTTPRoute", "frontend", "route", "public-gw", map[string]any{
				"name":      "api-svc",
				"namespace": "backend",
				"port":      int64(80),
			}),
			referenceGrant("backend", "allow-route", "gateway.networking.k8s.io", "HTTPRoute", "frontend", "", "Service", "api-svc"),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("backend", "api", "api", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true with matching ReferenceGrant: %#v", exposure)
	}
}

func TestAnalyzeUnprovisionedIngressIsExcludedAndGatewayWins(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("web", "web:v1"))
	pending := ingress("default", "pending-ing", "gce", "web-svc", nil)
	pending.Status.LoadBalancer.Ingress = nil // no load balancer provisioned
	objects := Objects{
		Services:  []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Ingresses: []networkingv1.Ingress{pending},
		Unstructured: []unstructured.Unstructured{
			gateway("default", "public-gw", "gke-l7-global-external-managed"),
			routeWithBackendRef("HTTPRoute", "default", "route", "public-gw", map[string]any{
				"name": "web-svc",
				"port": int64(80),
			}),
		},
	}

	got := Analyze(inv, objects)

	exposure := got[resourceRef("default", "web", "web", "container", "")]
	if !exposure.InternetAccessible {
		t.Fatalf("InternetAccessible = false, want true via gateway: %#v", exposure)
	}
	if exposure.RouteKind == "Ingress" {
		t.Fatalf("expected gateway exposure to win over unprovisioned ingress, got %#v", exposure)
	}
}

func TestAnalyzeUnprovisionedIngressAloneIsNotExposed(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("web", "web:v1"))
	pending := ingress("default", "pending-ing", "gce", "web-svc", nil)
	pending.Status.LoadBalancer.Ingress = nil
	objects := Objects{
		Services:  []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Ingresses: []networkingv1.Ingress{pending},
	}

	got := Analyze(inv, objects)

	if len(got) != 0 {
		t.Fatalf("Analyze() = %#v, want no exposure for an unprovisioned ingress", got)
	}
}

func TestAnalyzeUnstructuredKindCollisionsIgnoreUnexpectedAPIGroups(t *testing.T) {
	inv := inventoryWithWorkload("default", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
	objects := Objects{
		Services: []corev1.Service{service("default", "api-svc", map[string]string{"app": "api"})},
		IngressClasses: []networkingv1.IngressClass{
			ingressClass("alb", "ingress.k8s.aws/alb", "internet-facing-params"),
		},
		Ingresses: []networkingv1.Ingress{ingress("default", "params-alb", "alb", "api-svc", nil)},
		Unstructured: []unstructured.Unstructured{
			unstructuredWithGroup("example.com/v1", "IngressClassParams", "", "internet-facing-params", map[string]any{"scheme": "internet-facing"}),
			unstructuredWithGroup("example.com/v1", "Gateway", "default", "fake-gw", map[string]any{"gatewayClassName": "gke-l7-global-external-managed"}),
			route("HTTPRoute", "default", "fake-route", "fake-gw", "api-svc"),
		},
	}

	got := Analyze(inv, objects)

	if len(got) != 0 {
		t.Fatalf("Analyze() returned %#v, want no exposure from wrong API group kind collisions", got)
	}
}

func TestAnalyzeGatewayRouteKindsResolveBackendRefs(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute"} {
		t.Run(kind, func(t *testing.T) {
			inv := inventoryWithWorkload("default", "api", map[string]string{"app": "api"}, containerImage("api", "api:v1"))
			objects := Objects{
				Services: []corev1.Service{service("default", "api-svc", map[string]string{"app": "api"})},
				Unstructured: []unstructured.Unstructured{
					gateway("default", "public-gw", "gke-l7-global-external-managed"),
					route(kind, "default", "route", "public-gw", "api-svc"),
				},
			}

			got := Analyze(inv, objects)

			exposure := got[resourceRef("default", "api", "api", "container", "")]
			if !exposure.InternetAccessible {
				t.Fatalf("InternetAccessible = false, want true for %s: %#v", kind, exposure)
			}
			if exposure.RouteKind != kind {
				t.Fatalf("RouteKind = %q, want %q", exposure.RouteKind, kind)
			}
		})
	}
}

func TestAnalyzeIngressSelectorResolutionAndInitContainerRules(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"},
		containerImage("app", "web:v1"),
		initContainerImage("migrate", "migrate:v1", ""),
		initContainerImage("proxy", "proxy:v1", "Always"),
	)
	objects := Objects{
		Services:  []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Ingresses: []networkingv1.Ingress{ingress("default", "public-ing", "gce", "web-svc", nil)},
	}

	got := Analyze(inv, objects)

	app := got[resourceRef("default", "web", "app", "container", "")]
	if !app.InternetAccessible {
		t.Fatalf("app InternetAccessible = false, want true: %#v", app)
	}
	migrate := got[resourceRef("default", "web", "migrate", "initContainer", "")]
	if migrate.InternetAccessible {
		t.Fatalf("migrate InternetAccessible = true, want false: %#v", migrate)
	}
	requireEvidence(t, migrate, "init container default/web/migrate is not internet accessible because restartPolicy is not Always")
	proxy := got[resourceRef("default", "web", "proxy", "initContainer", "Always")]
	if !proxy.InternetAccessible {
		t.Fatalf("proxy InternetAccessible = false, want true: %#v", proxy)
	}
	requireEvidence(t, proxy, "sidecar init container default/web/proxy inherits exposure because restartPolicy is Always")
}

func TestAnalyzeUnknownIngressClassIsNotPublic(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{
		Services:  []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Ingresses: []networkingv1.Ingress{ingress("default", "unknown", "nginx", "web-svc", nil)},
	}

	got := Analyze(inv, objects)

	if len(got) != 0 {
		t.Fatalf("Analyze() returned %#v, want no exposure for unknown controller", got)
	}
}

func TestResourceInventoryRequiresLabelsForSelectorResolution(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", nil, containerImage("app", "web:v1"))
	objects := Objects{
		Services:  []corev1.Service{service("default", "web-svc", map[string]string{"app": "web"})},
		Ingresses: []networkingv1.Ingress{ingress("default", "public-ing", "gce", "web-svc", nil)},
	}

	got := Analyze(inv, objects)

	if len(got) != 0 {
		t.Fatalf("Analyze() returned %#v, want no exposure without workload labels", got)
	}
}

func inventoryWithWorkload(namespace, name string, labels map[string]string, images ...model.ContainerImage) *model.Inventory {
	return &model.Inventory{
		Resources: []model.ResourceInventory{{
			Resource: model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: namespace, Name: name},
			Labels:   labels,
			Images:   images,
		}},
	}
}

func containerImage(name, image string) model.ContainerImage {
	return model.ContainerImage{Name: name, ContainerType: "container", ImageRef: image}
}

func initContainerImage(name, image, restartPolicy string) model.ContainerImage {
	return model.ContainerImage{Name: name, ContainerType: "initContainer", ImageRef: image, RestartPolicy: restartPolicy}
}

func resourceRef(namespace, workload, containerName, containerType, restartPolicy string) model.ResourceRef {
	return model.ResourceRef{
		APIVersion:    "apps/v1",
		Kind:          "Deployment",
		Namespace:     namespace,
		Name:          workload,
		ContainerName: containerName,
		ContainerType: containerType,
		RestartPolicy: restartPolicy,
	}
}

func service(namespace, name string, selector map[string]string) corev1.Service {
	return serviceWithAnnotations(namespace, name, selector, nil)
}

func serviceWithAnnotations(namespace, name string, selector, annotations map[string]string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Annotations: annotations},
		Spec:       corev1.ServiceSpec{Selector: selector},
	}
}

func serviceWithPortsAndAnnotations(namespace, name string, selector, annotations map[string]string, ports ...corev1.ServicePort) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Annotations: annotations},
		Spec:       corev1.ServiceSpec{Selector: selector, Ports: ports},
	}
}

func servicePort(name string, port int32) corev1.ServicePort {
	return corev1.ServicePort{Name: name, Port: port}
}

func ingress(namespace, name, className, serviceName string, annotations map[string]string) networkingv1.Ingress {
	return ingressWithBackendPort(namespace, name, className, serviceName, networkingv1.ServiceBackendPort{Number: 80}, annotations)
}

func ingressWithServicePortName(namespace, name, className, serviceName, servicePortName string, annotations map[string]string) networkingv1.Ingress {
	return ingressWithBackendPort(namespace, name, className, serviceName, networkingv1.ServiceBackendPort{Name: servicePortName}, annotations)
}

func ingressWithBackendPort(namespace, name, className, serviceName string, port networkingv1.ServiceBackendPort, annotations map[string]string) networkingv1.Ingress {
	pathType := networkingv1.PathTypePrefix
	ing := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Annotations: annotations},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						PathType: &pathType,
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: serviceName,
							Port: port,
						}},
					}},
				}},
			}},
		},
	}
	if className != "" {
		ing.Spec.IngressClassName = &className
	}
	// Provisioned ingress: a load balancer address is assigned. Tests that need an
	// unprovisioned ingress clear this explicitly.
	ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: "203.0.113.10"}}
	return ing
}

func ingressClass(name, controller, paramsName string) networkingv1.IngressClass {
	return networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: networkingv1.IngressClassSpec{
			Controller: controller,
			Parameters: &networkingv1.IngressClassParametersReference{
				APIGroup: strPtr("elbv2.k8s.aws"),
				Kind:     "IngressClassParams",
				Name:     paramsName,
			},
		},
	}
}

func gateway(namespace, name, className string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"spec": map[string]any{"gatewayClassName": className},
	}}
}

func httpRoute(namespace, name, gatewayName, serviceName string) unstructured.Unstructured {
	return route("HTTPRoute", namespace, name, gatewayName, serviceName)
}

func route(kind, namespace, name, gatewayName, serviceName string) unstructured.Unstructured {
	return routeWithBackendRef(kind, namespace, name, gatewayName, map[string]any{"name": serviceName, "port": int64(80)})
}

func routeWithBackendRef(kind, namespace, name, gatewayName string, backendRef map[string]any) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": gatewayName}},
			"rules": []any{map[string]any{
				"backendRefs": []any{backendRef},
			}},
		},
	}}
}

func referenceGrant(namespace, name, fromGroup, fromKind, fromNamespace, toGroup, toKind, toName string) unstructured.Unstructured {
	to := map[string]any{"group": toGroup, "kind": toKind}
	if toName != "" {
		to["name"] = toName
	}
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1beta1",
		"kind":       "ReferenceGrant",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"spec": map[string]any{
			"from": []any{map[string]any{
				"group":     fromGroup,
				"kind":      fromKind,
				"namespace": fromNamespace,
			}},
			"to": []any{to},
		},
	}}
}

func unstructuredWithGroup(apiVersion, kind, namespace, name string, spec map[string]any) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"spec": spec,
	}}
}

func gcpBackendPolicyIAP(namespace, name, serviceName string, enabled bool) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.gke.io/v1",
		"kind":       "GCPBackendPolicy",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"spec": map[string]any{
			"default": map[string]any{"iap": map[string]any{"enabled": enabled}},
			"targetRef": map[string]any{
				"group": "",
				"kind":  "Service",
				"name":  serviceName,
			},
		},
	}}
}

func backendConfigIAP(namespace, name string, enabled bool) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cloud.google.com/v1",
		"kind":       "BackendConfig",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"spec": map[string]any{"iap": map[string]any{"enabled": enabled}},
	}}
}

func ingressClassParams(name, scheme string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "elbv2.k8s.aws/v1beta1",
		"kind":       "IngressClassParams",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"scheme": scheme},
	}}
}

func loadBalancerConfiguration(namespace, gatewayName, scheme string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.k8s.aws/v1beta1",
		"kind":       "LoadBalancerConfiguration",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      gatewayName,
		},
		"spec": map[string]any{"scheme": scheme},
	}}
}

func requireEvidence(t *testing.T, exposure model.Exposure, want string) {
	t.Helper()
	for _, got := range exposure.Evidence {
		if got == want {
			return
		}
	}
	t.Fatalf("missing evidence %q in %#v", want, exposure.Evidence)
}

func strPtr(v string) *string {
	return &v
}
