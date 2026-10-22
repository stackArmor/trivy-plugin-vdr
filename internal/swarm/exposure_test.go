package swarm

import (
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const testContext = "swarm/test"

func defaultExposureConfig() ExposureConfig {
	return ExposureConfig{ProxyLabelPrefixes: []string{DefaultProxyLabelPrefix}}
}

func fixtureWithNetworks(t *testing.T) []Service {
	t.Helper()
	doc := `{"services": ` + string(loadFixture(t)) + `, "networks": [
		{"ID": "hostnet00000000000000000id", "Name": "host", "Driver": "host"},
		{"ID": "net0000000000000000000public", "Name": "public", "Driver": "overlay"},
		{"ID": "net000000000000000000private", "Name": "private", "Driver": "overlay"}
	]}`
	services, err := ParseServices(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return services
}

func exposureFor(t *testing.T, exposures map[model.ResourceRef]model.Exposure, service Service) model.Exposure {
	t.Helper()
	exposure, ok := exposures[ContainerRef(testContext, service)]
	if !ok {
		t.Fatalf("no exposure for %s", service.Name)
	}
	return exposure
}

func hasEvidence(exposure model.Exposure, substring string) bool {
	for _, item := range exposure.Evidence {
		if strings.Contains(item, substring) {
			return true
		}
	}
	return false
}

func TestLabelDeclarationWins(t *testing.T) {
	service := Service{Name: "app_api", Stack: "app", Image: "api:1", NetworksResolved: true, Labels: map[string]string{
		ReachableLabel: "true",
	}}
	cfg := defaultExposureConfig()
	cfg.Rules = []ExposureRule{{Name: "app_api", InternetReachable: false, Justification: "rule says private"}}

	exposures, _ := AnalyzeExposure(testContext, []Service{service}, cfg)
	got := exposureFor(t, exposures, service)
	if !got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "attested" || got.Provider != Provider {
		t.Fatalf("exposure = %+v", got)
	}
	if !hasEvidence(got, "label "+ReachableLabel) {
		t.Fatalf("evidence = %v, want the declaring label", got.Evidence)
	}
}

func TestConfigRuleDeclaration(t *testing.T) {
	services := []Service{
		{Name: "edge_traefik", Stack: "edge", Image: "traefik:v3.1", NetworksResolved: true},
		{Name: "mon_exporter", Stack: "mon", Image: "prom/node-exporter:v1", NetworksResolved: true,
			Ports: []PublishedPort{{Protocol: "tcp", TargetPort: 9100, PublishedPort: 9100, PublishMode: "host"}}},
	}
	cfg := defaultExposureConfig()
	cfg.Rules = []ExposureRule{
		{Image: "traefik", InternetReachable: true},
		{Stack: "mon", Name: "*exporter", InternetReachable: false, Justification: "Private subnet only."},
	}
	exposures, warnings := AnalyzeExposure(testContext, services, cfg)
	if len(warnings) != 0 {
		t.Fatalf("declared services must not warn: %v", warnings)
	}
	traefik := exposureFor(t, exposures, services[0])
	if !traefik.InternetAccessible || traefik.AssessmentBasis != "attested" || !hasEvidence(traefik, "exposure.yaml rules[0]") {
		t.Fatalf("traefik = %+v", traefik)
	}
	exporter := exposureFor(t, exposures, services[1])
	if exporter.InternetAccessible || exporter.AssessmentStatus != "assessed" || !hasEvidence(exporter, JustificationEvidencePrefix+"Private subnet only.") {
		t.Fatalf("exporter = %+v", exporter)
	}
}

func TestAttestedFalseRequiresJustification(t *testing.T) {
	service := Service{Name: "app_scd", Stack: "app", Image: "scd:1", NetworksResolved: true, Labels: map[string]string{ReachableLabel: "false"}}
	exposures, warnings := AnalyzeExposure(testContext, []Service{service}, defaultExposureConfig())
	got := exposureFor(t, exposures, service)
	if got.AssessmentStatus != "unassessed" {
		t.Fatalf("exposure = %+v, want unassessed", got)
	}
	want := "service app_scd declares " + ReachableLabel + "=false without " + JustificationLabel
	if len(warnings) != 1 || !strings.Contains(warnings[0], want) {
		t.Fatalf("warnings = %v, want %q", warnings, want)
	}
}

func TestPublishedPortsWithoutDeclarationAreUnassessed(t *testing.T) {
	services := fixtureWithNetworks(t)
	exposures, warnings := AnalyzeExposure(testContext, services, defaultExposureConfig())
	got := exposureFor(t, exposures, serviceNamed(t, services, "edge_traefik"))
	if got.AssessmentStatus != "unassessed" || got.InternetAccessible || !hasEvidence(got, "publishes 443/tcp (ingress routing mesh)") {
		t.Fatalf("edge_traefik = %+v", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "edge_traefik") || !strings.Contains(warnings[0], ReachableLabel) {
		t.Fatalf("warnings = %v, want one summary naming edge_traefik", warnings)
	}
}

func TestTraefikRouteWithoutDeclarationIsUnassessed(t *testing.T) {
	services := fixtureWithNetworks(t)
	exposures, _ := AnalyzeExposure(testContext, services, defaultExposureConfig())
	got := exposureFor(t, exposures, serviceNamed(t, services, "app_web"))
	if got.AssessmentStatus != "unassessed" || !hasEvidence(got, "Host(`app.example.com`)") {
		t.Fatalf("app_web = %+v", got)
	}
}

func TestNoPortsNoRoutesIsObservedNegative(t *testing.T) {
	services := fixtureWithNetworks(t)
	exposures, _ := AnalyzeExposure(testContext, services, defaultExposureConfig())
	for _, name := range []string{"ops_web", "app_worker"} {
		got := exposureFor(t, exposures, serviceNamed(t, services, name))
		if got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "observed" || got.Provider != Provider {
			t.Fatalf("%s = %+v, want an observed negative", name, got)
		}
	}
}

func TestUnresolvedNetworksNeverObservedNegative(t *testing.T) {
	// A bare inspect array cannot tell an overlay network from the host network.
	services := parseFixture(t)
	exposures, _ := AnalyzeExposure(testContext, services, defaultExposureConfig())
	got := exposureFor(t, exposures, serviceNamed(t, services, "ops_web"))
	if got.AssessmentStatus != "unassessed" || !hasEvidence(got, "network list") {
		t.Fatalf("ops_web = %+v, want unassessed pending the network list", got)
	}
}

func TestHostNetworkNeverObservedNegative(t *testing.T) {
	services := fixtureWithNetworks(t)
	exposures, _ := AnalyzeExposure(testContext, services, defaultExposureConfig())
	got := exposureFor(t, exposures, serviceNamed(t, services, "netprobe"))
	if got.AssessmentStatus != "unassessed" || !hasEvidence(got, "host network") {
		t.Fatalf("netprobe = %+v", got)
	}
}

func TestHostModePortIsEvidence(t *testing.T) {
	services := fixtureWithNetworks(t)
	exposures, _ := AnalyzeExposure(testContext, services, defaultExposureConfig())
	got := exposureFor(t, exposures, serviceNamed(t, services, "mon_node-exporter"))
	if got.AssessmentStatus != "unassessed" || !hasEvidence(got, "publishes 9100/tcp (host mode)") {
		t.Fatalf("node-exporter = %+v", got)
	}
}

func TestAnyProxyLabelIsExposureEvidence(t *testing.T) {
	services := []Service{
		// Routed by Traefik's defaultRule: enabled, no explicit rule.
		{Name: "app_default", Stack: "app", Image: "a:1", NetworksResolved: true, Labels: map[string]string{
			"traefik.enable": "true", "traefik.http.services.x.loadbalancer.server.port": "8080",
		}},
		// A TCP router.
		{Name: "app_tcp", Stack: "app", Image: "b:1", NetworksResolved: true, Labels: map[string]string{
			"traefik.tcp.routers.db.rule": "HostSNI(`db.example.com`)",
		}},
		// A Caddy-routed service, with Caddy configured as an extra proxy.
		{Name: "app_caddy", Stack: "app", Image: "c:1", NetworksResolved: true, Labels: map[string]string{
			"caddy": "app.example.com", "caddy.reverse_proxy": "{{upstreams 80}}",
		}},
	}
	data, exposureConfig, err := ParseFedRAMPConfig([]byte("exposure.yaml: |\n  proxyLabelPrefixes:\n    - caddy\n"))
	if err != nil || len(data) != 0 {
		t.Fatal(err)
	}
	exposures, warnings := AnalyzeExposure(testContext, services, exposureConfig)
	for _, service := range services {
		if got := exposureFor(t, exposures, service); got.AssessmentStatus != "unassessed" {
			t.Fatalf("%s = %+v, want unassessed: a proxy label must never become an observed negative", service.Name, got)
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "app_default") || !strings.Contains(warnings[0], "app_caddy") {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestConfiguredProxyPrefixesExtendTheDefault(t *testing.T) {
	_, exposureConfig, err := ParseFedRAMPConfig([]byte("exposure.yaml: |\n  proxyLabelPrefixes:\n    - caddy\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(exposureConfig.ProxyLabelPrefixes, ",") != DefaultProxyLabelPrefix+",caddy" {
		t.Fatalf("prefixes = %v, want the Traefik default kept", exposureConfig.ProxyLabelPrefixes)
	}
}
