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

func TestTraefikRouteWithoutDeclarationIsInternetAccessible(t *testing.T) {
	services := fixtureWithNetworks(t)
	exposures, warnings := AnalyzeExposure(testContext, services, defaultExposureConfig())
	got := exposureFor(t, exposures, serviceNamed(t, services, "app_web"))
	if !got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "observed" || got.Provider != Provider || !hasEvidence(got, "Host(`app.example.com`)") {
		t.Fatalf("app_web = %+v, want observed internet-accessible with router rule evidence", got)
	}
	if strings.Contains(strings.Join(warnings, "\n"), "app_web") {
		t.Fatalf("warnings = %v, must not warn on proxy-routed app_web", warnings)
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

func TestAnyProxyLabelMarksInternetAccessible(t *testing.T) {
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
	data, exposureConfig, err := ParseFedRAMPConfig([]byte("exposure.yaml: |\n  proxyLabelPrefixes:\n    - traefik.\n    - caddy\n"))
	if err != nil || len(data) != 0 {
		t.Fatal(err)
	}
	exposures, warnings := AnalyzeExposure(testContext, services, exposureConfig)
	for _, service := range services {
		got := exposureFor(t, exposures, service)
		if !got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "observed" || got.Provider != Provider {
			t.Fatalf("%s = %+v, want observed internet-accessible", service.Name, got)
		}
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none for proxy-routed services", warnings)
	}
}

func TestTraefikDisableOptOutIsNotInternetAccessible(t *testing.T) {
	services := []Service{
		{Name: "app_disabled", Stack: "app", Image: "a:1", NetworksResolved: true, Labels: map[string]string{
			"traefik.enable":              "false",
			"traefik.http.routers.a.rule": "Host(`stale.example.com`)",
		}},
		{Name: "app_disabled_upper", Stack: "app", Image: "b:1", NetworksResolved: true, Labels: map[string]string{
			"traefik.enable": " FALSE ",
		}},
		// Non-Traefik proxy labels still apply even when traefik.enable=false.
		{Name: "app_caddy_only", Stack: "app", Image: "c:1", NetworksResolved: true, Labels: map[string]string{
			"traefik.enable": "false",
			"caddy":          "app.example.com",
		}},
	}
	_, exposureConfig, err := ParseFedRAMPConfig([]byte("exposure.yaml: |\n  proxyLabelPrefixes:\n    - traefik.\n    - caddy\n"))
	if err != nil {
		t.Fatal(err)
	}
	exposures, warnings := AnalyzeExposure(testContext, services, exposureConfig)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	for _, name := range []string{"app_disabled", "app_disabled_upper"} {
		var svc Service
		for _, s := range services {
			if s.Name == name {
				svc = s
			}
		}
		got := exposureFor(t, exposures, svc)
		if got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "observed" {
			t.Fatalf("%s = %+v, want observed negative when traefik.enable=false", name, got)
		}
	}
	caddy := exposureFor(t, exposures, services[2])
	if !caddy.InternetAccessible || caddy.AssessmentStatus != "assessed" || caddy.AssessmentBasis != "observed" {
		t.Fatalf("app_caddy_only = %+v, want observed internet-accessible via caddy label", caddy)
	}
}

func TestAttestedFalseOverridesTraefikLabels(t *testing.T) {
	services := []Service{
		{Name: "app_internal_label", Stack: "app", Image: "internal:1", NetworksResolved: true, Labels: map[string]string{
			"traefik.enable":                  "true",
			"traefik.http.routers.i.rule":     "Host(`internal.corp`)",
			ReachableLabel:                    "false",
			JustificationLabel:                "Internal Traefik entrypoint only.",
		}},
		{Name: "app_internal_rule", Stack: "app", Image: "admin:1", NetworksResolved: true, Labels: map[string]string{
			"traefik.enable":              "true",
			"traefik.http.routers.a.rule": "Host(`admin.corp`)",
		}},
	}
	cfg := defaultExposureConfig()
	cfg.Rules = []ExposureRule{{Image: "admin", InternetReachable: false, Justification: "VPN-only entrypoint."}}
	exposures, warnings := AnalyzeExposure(testContext, services, cfg)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	for _, svc := range services {
		got := exposureFor(t, exposures, svc)
		if got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "attested" {
			t.Fatalf("%s = %+v, want attested false overriding traefik labels", svc.Name, got)
		}
		if !hasEvidence(got, "proxy label traefik.enable=true") {
			t.Fatalf("%s evidence = %v, want proxy label preserved in evidence", svc.Name, got.Evidence)
		}
	}
}

func TestTraefikRouteWithUnresolvedNetworksIsStillInternetAccessible(t *testing.T) {
	services := parseFixture(t)
	exposures, _ := AnalyzeExposure(testContext, services, defaultExposureConfig())
	got := exposureFor(t, exposures, serviceNamed(t, services, "app_web"))
	if !got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "observed" {
		t.Fatalf("app_web = %+v, want observed internet-accessible even without network list", got)
	}
}

func TestTraefikRouteWithPublishedPortIsInternetAccessible(t *testing.T) {
	service := Service{
		Name: "printercloud_agent-api", Stack: "printercloud", Image: "agent-api:1", NetworksResolved: true,
		Ports: []PublishedPort{{Protocol: "tcp", TargetPort: 80, PublishedPort: 11780, PublishMode: "ingress"}},
		Labels: map[string]string{
			"traefik.enable":                      "true",
			"traefik.http.routers.agent-api.rule": "Host(`agent-api.example.com`)",
		},
	}
	exposures, warnings := AnalyzeExposure(testContext, []Service{service}, defaultExposureConfig())
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	got := exposureFor(t, exposures, service)
	if !got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "observed" {
		t.Fatalf("agent-api = %+v, want observed internet-accessible", got)
	}
	if !hasEvidence(got, "publishes 11780/tcp") || !hasEvidence(got, "Host(`agent-api.example.com`)") {
		t.Fatalf("evidence = %v, want both port and proxy label signals", got.Evidence)
	}
}

func TestConfiguredProxyPrefixesReplaceTheDefault(t *testing.T) {
	// Omitting proxyLabelPrefixes keeps the built-in Traefik default.
	_, omitted, err := ParseFedRAMPConfig([]byte("exposure.yaml: |\n  rules:\n    - image: edge\n      internetReachable: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(omitted.ProxyLabelPrefixes, ",") != DefaultProxyLabelPrefix {
		t.Fatalf("omitted prefixes = %v, want [%s]", omitted.ProxyLabelPrefixes, DefaultProxyLabelPrefix)
	}

	// Setting proxyLabelPrefixes replaces the default instead of appending.
	_, custom, err := ParseFedRAMPConfig([]byte("exposure.yaml: |\n  proxyLabelPrefixes:\n    - caddy\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(custom.ProxyLabelPrefixes, ",") != "caddy" {
		t.Fatalf("custom prefixes = %v, want [caddy]", custom.ProxyLabelPrefixes)
	}

	// An empty proxyLabelPrefixes list disables proxy-label inference.
	_, disabled, err := ParseFedRAMPConfig([]byte("exposure.yaml: |\n  proxyLabelPrefixes: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(disabled.ProxyLabelPrefixes) != 0 {
		t.Fatalf("disabled prefixes = %v, want empty", disabled.ProxyLabelPrefixes)
	}
	service := Service{
		Name: "app_internal_traefik", Stack: "app", Image: "web:1", NetworksResolved: true,
		Labels: map[string]string{"traefik.enable": "true", "traefik.http.routers.web.rule": "Host(`internal.corp`)"},
	}
	exposures, warnings := AnalyzeExposure(testContext, []Service{service}, disabled)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	got := exposureFor(t, exposures, service)
	if got.InternetAccessible || got.AssessmentStatus != "assessed" || got.AssessmentBasis != "observed" {
		t.Fatalf("exposure with proxyLabelPrefixes: [] = %+v, want observed negative", got)
	}
}
