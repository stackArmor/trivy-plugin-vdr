package swarm

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func loadFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/services.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func parseFixture(t *testing.T) []Service {
	t.Helper()
	services, err := ParseServices(bytes.NewReader(loadFixture(t)))
	if err != nil {
		t.Fatalf("ParseServices: %v", err)
	}
	return services
}

func serviceNamed(t *testing.T, services []Service, name string) Service {
	t.Helper()
	for _, service := range services {
		if service.Name == name {
			return service
		}
	}
	t.Fatalf("service %q not found", name)
	return Service{}
}

func TestParseServicesReadsInspectArray(t *testing.T) {
	services := parseFixture(t)
	if len(services) != 6 {
		t.Fatalf("services = %d, want 6", len(services))
	}

	web := serviceNamed(t, services, "app_web")
	if web.ID != "svc0000000000000000000002" || web.Stack != "app" || web.Mode != "replicated" {
		t.Fatalf("app_web = %+v", web)
	}
	if !strings.HasSuffix(web.Image, "@sha256:2222222222222222222222222222222222222222222222222222222222222222") {
		t.Fatalf("image lost its digest: %q", web.Image)
	}
	if web.Labels["traefik.http.routers.web.rule"] != "Host(`app.example.com`)" {
		t.Fatalf("labels = %v", web.Labels)
	}

	traefik := serviceNamed(t, services, "edge_traefik")
	if len(traefik.Ports) != 2 || traefik.Ports[0] != (PublishedPort{Protocol: "tcp", TargetPort: 443, PublishedPort: 443, PublishMode: "ingress"}) {
		t.Fatalf("traefik ports = %+v", traefik.Ports)
	}

	exporter := serviceNamed(t, services, "mon_node-exporter")
	if exporter.Mode != "global" || len(exporter.Ports) != 1 || exporter.Ports[0].PublishMode != "host" {
		t.Fatalf("node-exporter = %+v", exporter)
	}

	probe := serviceNamed(t, services, "netprobe")
	if probe.Stack != DefaultStack {
		t.Fatalf("unstacked service stack = %q, want %q", probe.Stack, DefaultStack)
	}
	if probe.HostNetwork {
		t.Fatal("a bare inspect array cannot resolve the host network ID")
	}
}

func TestParseServicesResolvesHostNetworkFromNetworkList(t *testing.T) {
	doc := `{"services": ` + string(loadFixture(t)) + `, "networks": [
		{"ID": "hostnet00000000000000000id", "Name": "host", "Driver": "host"},
		{"ID": "net0000000000000000000public", "Name": "public", "Driver": "overlay"}
	]}`
	services, err := ParseServices(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ParseServices: %v", err)
	}
	if !serviceNamed(t, services, "netprobe").HostNetwork {
		t.Fatal("netprobe should be on the host network")
	}
	web := serviceNamed(t, services, "app_web")
	if web.HostNetwork || len(web.Networks) != 1 || web.Networks[0] != "public" {
		t.Fatalf("app_web networks = %v host=%v", web.Networks, web.HostNetwork)
	}
}

func TestParseServicesAcceptsLiteralHostTarget(t *testing.T) {
	doc := `[{"ID": "x", "Spec": {"Name": "probe", "TaskTemplate": {"ContainerSpec": {"Image": "busybox"}, "Networks": [{"Target": "host"}]}}}]`
	services, err := ParseServices(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !services[0].HostNetwork {
		t.Fatal("Target \"host\" should mark host networking")
	}
}

func TestParseServicesRejectsNonArray(t *testing.T) {
	_, err := ParseServices(strings.NewReader(`"not services"`))
	if err == nil || !strings.Contains(err.Error(), "docker service inspect") {
		t.Fatalf("err = %v, want a hint naming docker service inspect", err)
	}
}

func TestParseServicesSkipsServicesWithoutImage(t *testing.T) {
	doc := `[{"ID": "x", "Spec": {"Name": "empty", "TaskTemplate": {"ContainerSpec": {}}}}]`
	services, err := ParseServices(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 0 {
		t.Fatalf("services = %+v, want none", services)
	}
}

func TestBuildInventoryRefs(t *testing.T) {
	inventory := BuildInventory("swarm/test", parseFixture(t))
	if inventory.ContextName != "swarm/test" {
		t.Fatalf("context = %q", inventory.ContextName)
	}
	if len(inventory.Resources) != 6 {
		t.Fatalf("resources = %d, want 6", len(inventory.Resources))
	}

	var web model.ResourceInventory
	for _, resource := range inventory.Resources {
		if resource.Resource.Name == "app_web" {
			web = resource
		}
	}
	want := model.ResourceRef{
		APIVersion:  "swarm.docker.com/v1",
		Kind:        "Service",
		Provider:    Provider,
		Namespace:   "app",
		Name:        "app_web",
		UID:         "svc0000000000000000000002",
		CanonicalID: "docker-swarm://swarm%2Ftest/service/app_web",
		DisplayID:   "docker-swarm://swarm%2Ftest/service/app_web",
	}
	if web.Resource != want {
		t.Fatalf("resource = %+v\nwant       %+v", web.Resource, want)
	}
	if web.Labels["traefik.enable"] != "true" {
		t.Fatalf("labels not copied: %v", web.Labels)
	}
	if len(web.Images) != 1 || web.Images[0].Name != "app_web" || web.Images[0].ContainerType != "container" {
		t.Fatalf("images = %+v", web.Images)
	}

	var shared *model.ImageInventory
	for i := range inventory.Images {
		if strings.Contains(inventory.Images[i].ImageRef, "/web:2.4@") {
			shared = &inventory.Images[i]
		}
	}
	if shared == nil || len(shared.Resources) != 2 {
		t.Fatalf("shared image = %+v, want two resources", shared)
	}
	ref := shared.Resources[0]
	if ref.ContainerName != ref.Name || ref.ContainerType != "container" || ref.CanonicalID != "docker-swarm://swarm%2Ftest/service/"+ref.Name {
		t.Fatalf("container ref = %+v", ref)
	}
	if shared.NormalizedImage != "123456789012.dkr.ecr.us-east-1.amazonaws.com/web" {
		t.Fatalf("normalized = %q", shared.NormalizedImage)
	}
}
