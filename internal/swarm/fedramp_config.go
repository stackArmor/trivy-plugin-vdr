package swarm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// FedRAMPConfigName is the Swarm config object the scanner reads. It is
// deployed into the swarm, never mounted into a service.
const FedRAMPConfigName = "vdr-fedramp"

// DefaultProxyLabelPrefix marks a service as routed by Traefik.
const DefaultProxyLabelPrefix = "traefik.http.routers."

// exposureKey is the vdr-fedramp key holding the exposure declarations. Every
// other key is cluster scoring data with the same meaning as the Kubernetes
// vdr-fedramp ConfigMap.
const exposureKey = "exposure.yaml"

// ExposureConfig declares internet reachability for Swarm services, which have
// no ingress objects to discover it from.
type ExposureConfig struct {
	ProxyLabelPrefixes []string       `yaml:"proxyLabelPrefixes"`
	Rules              []ExposureRule `yaml:"rules"`
}

// ExposureRule declares reachability for services matching every set glob.
// An empty glob matches anything.
type ExposureRule struct {
	Stack             string `yaml:"stack"`
	Name              string `yaml:"name"`
	Image             string `yaml:"image"`
	InternetReachable bool   `yaml:"internetReachable"`
	Justification     string `yaml:"justification"`
}

// LoadFedRAMPConfig reads the vdr-fedramp config from either the output of
// `docker config inspect vdr-fedramp` (whose Spec.Data is base64) or the plain
// YAML file. It returns the scoring data, ready for
// scoring.Config.ApplyClusterDefaults, and the exposure declarations. An empty
// inspect result means the config does not exist, which is not an error.
func LoadFedRAMPConfig(path string) (map[string]string, ExposureConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ExposureConfig{ProxyLabelPrefixes: []string{DefaultProxyLabelPrefix}}, fmt.Errorf("read %s config: %w", FedRAMPConfigName, err)
	}
	return ParseFedRAMPConfig(raw)
}

// ParseFedRAMPConfig is LoadFedRAMPConfig for content already in memory, such
// as the output collected over SSM.
func ParseFedRAMPConfig(raw []byte) (map[string]string, ExposureConfig, error) {
	exposure := ExposureConfig{ProxyLabelPrefixes: []string{DefaultProxyLabelPrefix}}
	content, err := configContent(raw)
	if err != nil {
		return nil, exposure, err
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return map[string]string{}, exposure, nil
	}

	var document map[string]any
	if err := yaml.Unmarshal(content, &document); err != nil {
		return nil, exposure, fmt.Errorf("parse %s config: %w", FedRAMPConfigName, err)
	}
	data := make(map[string]string, len(document))
	for key, value := range document {
		switch typed := value.(type) {
		case nil:
			continue
		case string:
			data[key] = typed
		case bool, int, float64:
			// Accept unquoted scalars such as multiAgency: true.
			data[key] = fmt.Sprint(typed)
		default:
			return nil, exposure, fmt.Errorf("%s config key %q must be a string; embed documents as a block scalar (key: |)", FedRAMPConfigName, key)
		}
	}

	if doc := data[exposureKey]; strings.TrimSpace(doc) != "" {
		var declared struct {
			ProxyLabelPrefixes []string `yaml:"proxyLabelPrefixes"`
			Rules              []struct {
				Stack             string `yaml:"stack"`
				Name              string `yaml:"name"`
				Image             string `yaml:"image"`
				InternetReachable *bool  `yaml:"internetReachable"`
				Justification     string `yaml:"justification"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal([]byte(doc), &declared); err != nil {
			return nil, exposure, fmt.Errorf("parse %s config (%s): %w", FedRAMPConfigName, exposureKey, err)
		}
		if len(declared.ProxyLabelPrefixes) > 0 {
			exposure.ProxyLabelPrefixes = declared.ProxyLabelPrefixes
		}
		for i, rule := range declared.Rules {
			if rule.InternetReachable == nil {
				return nil, exposure, fmt.Errorf("%s config (%s): rules[%d] must set internetReachable", FedRAMPConfigName, exposureKey, i)
			}
			exposure.Rules = append(exposure.Rules, ExposureRule{
				Stack:             rule.Stack,
				Name:              rule.Name,
				Image:             rule.Image,
				InternetReachable: *rule.InternetReachable,
				Justification:     strings.TrimSpace(rule.Justification),
			})
		}
	}
	delete(data, exposureKey)
	return data, exposure, nil
}

// configContent unwraps `docker config inspect` output; anything that is not a
// JSON array is taken to be the YAML file itself.
func configContent(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trimmed, []byte("[")) {
		return raw, nil
	}
	var inspected []struct {
		Spec struct {
			Name string `json:"Name"`
			Data string `json:"Data"`
		} `json:"Spec"`
	}
	// Decode only the first array: output collected from a failed inspect can
	// carry more than one.
	if err := json.NewDecoder(bytes.NewReader(trimmed)).Decode(&inspected); err != nil {
		return nil, fmt.Errorf("parse docker config inspect output: %w", err)
	}
	if len(inspected) == 0 {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(inspected[0].Spec.Data)
	if err != nil {
		return nil, fmt.Errorf("decode %s config data: %w", inspected[0].Spec.Name, err)
	}
	return decoded, nil
}
