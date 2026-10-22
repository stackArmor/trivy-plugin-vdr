package swarm

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/scoring"
)

const sampleFedRAMPYAML = `class: "C"
multiAgency: true
securityRequirementsCeiling: cr-h_ir-h_ar-m
scoring.yaml: |
  imageRules:
    - match: auth
      securityImpactProfile: root-secrets.identity-control.shared-degradation
    - match: web-ui-*
      securityImpactProfile: CR:M/IR:M/AR:L
exposure.yaml: |
  proxyLabelPrefixes:
    - traefik.http.routers.
    - caddy
  rules:
    - image: traefik
      internetReachable: true
    - stack: mon
      name: "*exporter"
      internetReachable: false
      justification: "Host-mode port on the private subnet only."
`

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFedRAMPConfigFromPlainYAML(t *testing.T) {
	data, exposure, err := LoadFedRAMPConfig(writeFile(t, "vdr-fedramp.yaml", sampleFedRAMPYAML))
	if err != nil {
		t.Fatalf("LoadFedRAMPConfig: %v", err)
	}
	if data["class"] != "C" || data["multiAgency"] != "true" || data["securityRequirementsCeiling"] != "cr-h_ir-h_ar-m" {
		t.Fatalf("scalars = %v", data)
	}
	if !strings.Contains(data["scoring.yaml"], "match: auth") {
		t.Fatalf("scoring.yaml not passed through: %q", data["scoring.yaml"])
	}
	if _, present := data["exposure.yaml"]; present {
		t.Fatal("exposure.yaml belongs to the exposure config, not the scoring defaults")
	}
	if len(exposure.ProxyLabelPrefixes) != 2 || exposure.ProxyLabelPrefixes[1] != "caddy" {
		t.Fatalf("proxy prefixes = %v", exposure.ProxyLabelPrefixes)
	}
	if len(exposure.Rules) != 2 || !exposure.Rules[0].InternetReachable || exposure.Rules[0].Image != "traefik" {
		t.Fatalf("rules = %+v", exposure.Rules)
	}
	if exposure.Rules[1].Stack != "mon" || exposure.Rules[1].Name != "*exporter" || exposure.Rules[1].InternetReachable || exposure.Rules[1].Justification == "" {
		t.Fatalf("negative rule = %+v", exposure.Rules[1])
	}
}

func TestLoadFedRAMPConfigFromDockerInspect(t *testing.T) {
	inspect := []map[string]any{{
		"ID":   "cfg1",
		"Spec": map[string]any{"Name": "vdr-fedramp", "Data": base64.StdEncoding.EncodeToString([]byte(sampleFedRAMPYAML))},
	}}
	raw, _ := json.Marshal(inspect)
	data, exposure, err := LoadFedRAMPConfig(writeFile(t, "vdr-fedramp.json", string(raw)))
	if err != nil {
		t.Fatalf("LoadFedRAMPConfig: %v", err)
	}
	if data["class"] != "C" || len(exposure.Rules) != 2 {
		t.Fatalf("data=%v rules=%d", data, len(exposure.Rules))
	}
}

func TestLoadFedRAMPConfigEmptyInspectIsNoConfig(t *testing.T) {
	data, exposure, err := LoadFedRAMPConfig(writeFile(t, "missing.json", "[]\n"))
	if err != nil {
		t.Fatalf("an absent config (docker config inspect printed []) must not be an error: %v", err)
	}
	if len(data) != 0 || len(exposure.Rules) != 0 {
		t.Fatalf("data=%v exposure=%+v", data, exposure)
	}
	if len(exposure.ProxyLabelPrefixes) != 1 || exposure.ProxyLabelPrefixes[0] != DefaultProxyLabelPrefix {
		t.Fatalf("default proxy prefix missing: %v", exposure.ProxyLabelPrefixes)
	}
}

func TestLoadFedRAMPConfigMalformedPart(t *testing.T) {
	_, _, err := LoadFedRAMPConfig(writeFile(t, "bad.yaml", "class: B\nexposure.yaml: |\n  rules: [unterminated\n"))
	if err == nil || !strings.Contains(err.Error(), "exposure.yaml") {
		t.Fatalf("err = %v, want one naming exposure.yaml", err)
	}
	_, _, err = LoadFedRAMPConfig(writeFile(t, "norule.yaml", "exposure.yaml: |\n  rules:\n    - image: web\n"))
	if err == nil || !strings.Contains(err.Error(), "internetReachable") {
		t.Fatalf("err = %v, want a rule without internetReachable to be rejected", err)
	}
	data, _, err := LoadFedRAMPConfig(writeFile(t, "scalars.yaml", "class: B\n"))
	if err != nil || data["class"] != "B" {
		t.Fatalf("scoring.yaml is optional: data=%v err=%v", data, err)
	}
}

func TestExampleConfigParses(t *testing.T) {
	data, exposure, err := LoadFedRAMPConfig("../../examples/swarm/vdr-fedramp.yaml")
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	sc := scoring.Default()
	if err := sc.ApplyClusterDefaults(data); err != nil {
		t.Fatalf("example scoring.yaml does not validate: %v", err)
	}
	if len(sc.ImageRules) != 19 || len(sc.NameRules) != 1 {
		t.Fatalf("example rules: %d image, %d name; want 19 and 1", len(sc.ImageRules), len(sc.NameRules))
	}
	if len(exposure.Rules) != 4 {
		t.Fatalf("example exposure rules = %d, want 4", len(exposure.Rules))
	}
}
