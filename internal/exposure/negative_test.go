package exposure

import (
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestCompletedDiscoveryEmitsPerContainerNegatives(t *testing.T) {
	inv := inventoryWithWorkload("default", "internal", map[string]string{"app": "internal"},
		containerImage("app", "app:v1"),
		model.ContainerImage{Name: "setup", ContainerType: "initContainer", ImageRef: "setup:v1"},
		model.ContainerImage{Name: "sidecar", ContainerType: "initContainer", RestartPolicy: "Always", ImageRef: "sidecar:v1"})
	for _, complete := range []bool{false, true} {
		got := Analyze(inv, Objects{CollectionComplete: complete})
		if !complete {
			if len(got) != 0 {
				t.Fatalf("incomplete analysis synthesized negatives: %#v", got)
			}
			continue
		}
		if len(got) != 3 {
			t.Fatalf("got %d entries, want all three containers", len(got))
		}
		for _, ex := range got {
			if ex.InternetAccessible || ex.AssessmentStatus != "assessed" || ex.AssessmentBasis != "observed" || len(ex.Evidence) == 0 {
				t.Fatalf("missing completed negative evidence: %#v", ex)
			}
		}
	}
	if got := AnalyzeWithOptions(inv, Objects{CollectionComplete: true}, AnalyzeOptions{Declared: true}); len(got) != 0 {
		t.Fatalf("declared topology synthesized runtime negatives: %#v", got)
	}
	inv.Resources[0].DirectNodeAccess = true
	if got := Analyze(inv, Objects{CollectionComplete: true}); len(got) != 0 {
		t.Fatalf("hostNetwork/hostPort workload cannot receive a Service-only negative: %#v", got)
	}
}

func TestCompletedDiscoveryRetainsExistingPositiveRoutes(t *testing.T) {
	inv := inventoryWithWorkload("default", "web", map[string]string{"app": "web"}, containerImage("app", "web:v1"))
	objects := Objects{CollectionComplete: true}
	// Reuse the real Service/Ingress analysis through a public service fixture.
	svc := service("default", "web", map[string]string{"app": "web"})
	svc.Spec.Type = "LoadBalancer"
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "8.8.8.8"}}
	objects.Services = append(objects.Services, svc)
	got := Analyze(inv, objects)
	ref := resourceRef("default", "web", "app", "container", "")
	if ex := got[ref]; !ex.InternetAccessible {
		t.Fatalf("positive exposure replaced: %#v", ex)
	}
	objects.Services[0].Status.LoadBalancer.Ingress = nil
	if got := Analyze(inv, objects); len(got) != 0 {
		t.Fatalf("pending LB synthesized negative: %#v", got)
	}
}
