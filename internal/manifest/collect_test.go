package manifest

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/exposure"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
)

func TestCollectMergesRenderedApplicationAndGatewayObjects(t *testing.T) {
	application := []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  labels:
    app: web
spec:
  replicas: 2
  selector:
    matchLabels: {app: web}
  template:
    metadata:
      labels: {app: web}
    spec:
      containers:
        - name: app
          image: ghcr.io/acme/web:1.2.3
---
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  selector: {app: web}
  ports:
    - port: 80
`)
	edge := []byte(`
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
spec:
  gatewayClassName: gke-l7-global-external-managed
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web
spec:
  parentRefs:
    - name: public
  rules:
    - backendRefs:
        - name: web
          port: 80
`)

	result, err := Collect(context.Background(), []Document{
		{Name: "app", YAML: application, DefaultNamespace: "prod"},
		{Name: "edge", YAML: edge, DefaultNamespace: "prod"},
	}, Options{
		ContextName:     "helm:app",
		ClusterDefaults: map[string]string{"class": "C", "multiAgency": "true"},
	}, log.NewWithWriter(io.Discard, log.LevelQuiet))
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(result.Inventory.Resources) != 1 || len(result.Inventory.Images) != 1 {
		t.Fatalf("inventory resources/images = %d/%d", len(result.Inventory.Resources), len(result.Inventory.Images))
	}
	resource := result.Inventory.Resources[0]
	if resource.Resource.Namespace != "prod" || resource.Images[0].ImageRef != "ghcr.io/acme/web:1.2.3" {
		t.Fatalf("resource = %#v", resource)
	}
	if result.Inventory.ClusterDefaults["class"] != "C" {
		t.Fatalf("ClusterDefaults = %#v", result.Inventory.ClusterDefaults)
	}
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "cluster FedRAMP ConfigMap") {
			t.Fatalf("explicit defaults should suppress missing ConfigMap warning: %q", warning)
		}
	}
	if len(result.ExposureObjects.Services) != 1 || len(result.ExposureObjects.Unstructured) != 4 {
		t.Fatalf("exposure objects = %#v", result.ExposureObjects)
	}
	for _, object := range result.ExposureObjects.Unstructured {
		if object.GetKind() == "Gateway" && object.GetNamespace() != "prod" {
			t.Fatalf("Gateway namespace = %q, want prod", object.GetNamespace())
		}
	}
	exposures := exposure.AnalyzeWithOptions(result.Inventory, result.ExposureObjects, exposure.AnalyzeOptions{Declared: true})
	if len(exposures) != 1 {
		t.Fatalf("declared cross-chart exposures = %#v, want one application container", exposures)
	}
	for _, item := range exposures {
		if !item.InternetAccessible || item.RouteKind != "HTTPRoute" || item.AssessmentBasis != "declared" {
			t.Fatalf("declared Gateway exposure = %#v", item)
		}
	}
}

func TestCollectIncludesRenderedDaemonSetWithoutRuntimeStatus(t *testing.T) {
	manifest := []byte(`
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: agent
spec:
  selector:
    matchLabels: {app: agent}
  template:
    metadata:
      labels: {app: agent}
    spec:
      containers:
        - name: agent
          image: agent:v1
`)
	result, err := Collect(context.Background(), []Document{{Name: "agent", YAML: manifest, DefaultNamespace: "default"}}, Options{}, log.NewWithWriter(io.Discard, log.LevelQuiet))
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(result.Inventory.Resources) != 1 || result.Inventory.Resources[0].Resource.Kind != "DaemonSet" {
		t.Fatalf("Inventory = %#v, want rendered DaemonSet", result.Inventory)
	}
}

func TestCollectUsesRenderedImagePullSecret(t *testing.T) {
	dockerConfig := base64.StdEncoding.EncodeToString([]byte(`{"auths":{"registry.example.com":{"username":"user","password":"password","auth":"dXNlcjpwYXNzd29yZA=="}}}`))
	rendered := []byte(fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: registry-auth
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: %s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: private
spec:
  selector:
    matchLabels: {app: private}
  template:
    metadata:
      labels: {app: private}
    spec:
      imagePullSecrets:
        - name: registry-auth
      containers:
        - name: app
          image: registry.example.com/app:v1
`, dockerConfig))
	result, err := Collect(context.Background(), []Document{{Name: "private", YAML: rendered, DefaultNamespace: "prod"}}, Options{CollectPullSecrets: true}, log.NewWithWriter(io.Discard, log.LevelQuiet))
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	auth, ok := result.PullSecretAuths["registry.example.com"]
	if !ok || auth.Username != "user" || auth.Password != "password" {
		t.Fatalf("PullSecretAuths = %#v", result.PullSecretAuths)
	}
}

func TestCollectRejectsDuplicateObjectsAcrossCharts(t *testing.T) {
	object := []byte(`apiVersion: v1
kind: Service
metadata:
  name: duplicate
`)
	_, err := Collect(context.Background(), []Document{
		{Name: "app", YAML: object, DefaultNamespace: "default"},
		{Name: "edge", YAML: object, DefaultNamespace: "default"},
	}, Options{}, log.NewWithWriter(io.Discard, log.LevelQuiet))
	if err == nil || !strings.Contains(err.Error(), "duplicate rendered object") {
		t.Fatalf("error = %v, want duplicate object error", err)
	}
}

func TestCollectIgnoresDuplicateNonAnalysisHooksWithinChart(t *testing.T) {
	rendered := []byte(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: shared-hook
  annotations:
    helm.sh/hook: pre-install
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: shared-hook
  labels:
    rendered-by: another-subchart
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  selector:
    matchLabels: {app: app}
  template:
    metadata:
      labels: {app: app}
    spec:
      containers:
        - name: app
          image: app:v1
`)
	result, err := Collect(context.Background(), []Document{{Name: "app-chart", YAML: rendered, DefaultNamespace: "default"}}, Options{}, log.NewWithWriter(io.Discard, log.LevelQuiet))
	if err != nil {
		t.Fatalf("Collect returned error for duplicate non-analysis hooks: %v", err)
	}
	if len(result.Inventory.Resources) != 1 || result.Inventory.Resources[0].Resource.Name != "app" {
		t.Fatalf("Inventory = %#v, want app Deployment", result.Inventory)
	}
}

func TestLoadConfigMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vdr-fedramp.yaml")
	if err := os.WriteFile(path, []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: custom-vdr
data:
  class: D
  multiAgency: "true"
  internetAccessibleGatewayClasses: |
    - istio
`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := LoadConfigMap(path)
	if err != nil {
		t.Fatalf("LoadConfigMap returned error: %v", err)
	}
	if data["class"] != "D" || data["multiAgency"] != "true" || !strings.Contains(data["internetAccessibleGatewayClasses"], "istio") {
		t.Fatalf("ConfigMap data = %#v", data)
	}
}
