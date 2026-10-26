// Package cloudpolicy applies reviewed cloud assignments for standalone scans.
// The document contract and attribute precedence match TSW's cloud policy.
package cloudpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scoring"
	"gopkg.in/yaml.v3"
)

type values struct {
	Profile       string `yaml:"securityImpactProfile"`
	Class         string `yaml:"class"`
	Multi         string `yaml:"multiAgency"`
	Reachable     string `yaml:"internetReachable"`
	Justification string `yaml:"internetReachableJustification"`
}

type rule struct {
	values     `yaml:",inline"`
	Type       string            `yaml:"type"`
	Match      string            `yaml:"match"`
	MatchRegex string            `yaml:"matchRegex"`
	Region     string            `yaml:"region"`
	MatchTags  map[string]string `yaml:"matchTags"`
	Network    string            `yaml:"network"`
	Subnet     string            `yaml:"subnet"`
}

type scope struct {
	values       `yaml:",inline"`
	Provider     string `yaml:"provider"`
	Project      string `yaml:"project"`
	Account      string `yaml:"account"`
	Subscription string `yaml:"subscription"`
	NameRules    []rule `yaml:"nameRules"`
	TagRules     []rule `yaml:"tagRules"`
	NetworkRules []rule `yaml:"networkRules"`
	TypeRules    []rule `yaml:"typeRules"`
}

type document struct {
	APIVersion string                       `yaml:"apiVersion"`
	Kind       string                       `yaml:"kind"`
	Defaults   values                       `yaml:"defaults"`
	Scopes     []scope                      `yaml:"scopes"`
	Archetypes map[string]scoring.Archetype `yaml:"archetypes"`
}

// glob follows fnmatchcase semantics: '*' also matches '/' in resource names.
func glob(pattern, value string) (bool, error) {
	return path.Match(strings.ReplaceAll(pattern, "/", "\x01"), strings.ReplaceAll(value, "/", "\x01"))
}

func (r rule) matches(ref model.ResourceRef, providerType string, labels map[string]string, family string) (bool, error) {
	if family == "tagRules" && len(r.MatchTags) == 0 {
		return false, fmt.Errorf("tagRules requires nonempty matchTags")
	}
	if family == "typeRules" && r.Type == "" {
		return false, fmt.Errorf("typeRules requires an explicit type")
	}
	if family == "networkRules" && r.Network == "" {
		return false, fmt.Errorf("networkRules requires network")
	}
	if r.Type != "" && r.Type != providerType {
		return false, nil
	}
	if r.Region != "" {
		ok, err := glob(r.Region, ref.Region)
		if err != nil || !ok {
			return false, err
		}
	}
	for key, pattern := range r.MatchTags {
		value, exists := labels[key]
		if !exists {
			return false, nil
		}
		ok, err := glob(pattern, value)
		if err != nil || !ok {
			return false, err
		}
	}
	if family == "nameRules" {
		if r.MatchRegex != "" {
			if r.Match != "" || r.Type == "" || len(r.MatchRegex) > 2048 {
				return false, fmt.Errorf("matchRegex needs an explicit type and cannot be combined with match")
			}
			expression, err := regexp.Compile("^(?:" + r.MatchRegex + ")$")
			if err != nil {
				return false, err
			}
			return expression.MatchString(ref.Name), nil
		}
		if r.Match == "" {
			return false, fmt.Errorf("nameRules requires match or matchRegex")
		}
		return glob(r.Match, ref.Name)
	}
	if family == "networkRules" {
		// These collectors do not yet carry a complete network-attachment graph.
		// Falling through to a broader rule would silently differ from TSW.
		return false, fmt.Errorf("applicable networkRules requires cloud inventory network facts; use stackArmor-managed policy association")
	}
	return true, nil
}

func (v values) attribute(name string) string {
	switch name {
	case "securityImpactProfile":
		return v.Profile
	case "class":
		return v.Class
	case "multiAgency":
		return v.Multi
	case "internetReachable":
		return v.Reachable
	}
	return ""
}

func labelValue(labels map[string]string, attribute string, gcp bool) (string, bool) {
	suffix := map[string]string{"securityImpactProfile": "security-impact-profile", "class": "class", "multiAgency": "multi-agency", "internetReachable": "internet-reachable"}[attribute]
	for _, key := range []string{"vdr.fedramp.io/" + suffix, "vdr_fedramp_io_" + strings.ReplaceAll(suffix, "-", "_")} {
		if value, exists := labels[key]; exists {
			if gcp && attribute == "securityImpactProfile" {
				return strings.ReplaceAll(strings.TrimSpace(value), "__", "."), true
			}
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func validateStrings(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i].Value, node.Content[i+1]
			if key == "metadata" || key == "archetypes" || key == "matchTags" {
				continue
			}
			if key == "class" || key == "multiAgency" || key == "securityImpactProfile" || key == "internetReachable" || key == "account" || key == "project" {
				if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
					return fmt.Errorf("%s must be a quoted string", key)
				}
			}
			if err := validateStrings(value); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateStrings(child); err != nil {
			return err
		}
	}
	return nil
}

// Apply resolves each attribute independently: resource overrides, first matching
// name/tag/network/type rule, scope defaults, document defaults. Class is a scope
// attribute and does not come from resource rules, matching TSW's evaluator.
func Apply(filename string, inventory *model.Inventory, config *scoring.Config, exposures map[model.ResourceRef]model.Exposure) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var tree yaml.Node
	if err = yaml.Unmarshal(data, &tree); err != nil {
		return err
	}
	if err = validateStrings(&tree); err != nil {
		return err
	}
	var doc document
	if err = tree.Decode(&doc); err != nil {
		return err
	}
	if doc.APIVersion != "vdr.fedramp.io/v1alpha1" || doc.Kind != "CloudResourceScoringConfig" || len(doc.Scopes) == 0 {
		return fmt.Errorf("cloud config must be a vdr.fedramp.io/v1alpha1 CloudResourceScoringConfig with scopes")
	}
	if doc.Defaults.Class == "" || doc.Defaults.Reachable != "" {
		return fmt.Errorf("cloud config requires defaults.class and cannot set document-wide internetReachable")
	}
	if inventory == nil || inventory.Cloud == nil || inventory.Cloud.AccountID == "" {
		return fmt.Errorf("cloud config requires an identified cloud account/project")
	}
	var selected *scope
	scopeIndex := -1
	for i := range doc.Scopes {
		s := &doc.Scopes[i]
		identity := s.Account
		if s.Provider == "gcp" {
			identity = s.Project
		}
		if s.Provider == inventory.Cloud.Provider && identity == inventory.Cloud.AccountID {
			if selected != nil {
				return fmt.Errorf("cloud config has duplicate matching scopes")
			}
			selected = s
			scopeIndex = i
		}
	}
	if selected == nil {
		return fmt.Errorf("cloud config has no scope for %s/%s", inventory.Cloud.Provider, inventory.Cloud.AccountID)
	}
	for _, v := range []values{doc.Defaults, selected.values} {
		if v.Class != "" && v.Class != "A" && v.Class != "B" && v.Class != "C" && v.Class != "D" {
			return fmt.Errorf("cloud policy class must be A, B, C, or D")
		}
		if v.Multi != "" && v.Multi != "true" && v.Multi != "false" {
			return fmt.Errorf("cloud policy multiAgency must be a quoted true or false")
		}
	}
	for name, profile := range doc.Archetypes {
		if err = config.AddCloudArchetype(name, profile); err != nil {
			return err
		}
	}
	digest := sha256.Sum256(data)
	evidence := &model.CloudPolicyEvidence{SHA256: hex.EncodeToString(digest[:])}
	for i := range inventory.Resources {
		resource := &inventory.Resources[i]
		ref := resource.Resource
		providerType := "AWS::ECS::TaskDefinition"
		if inventory.Cloud.Provider == "gcp" {
			providerType = "run.googleapis.com/Service"
			if ref.Kind == "Job" {
				providerType = "run.googleapis.com/Job"
			}
		}
		resolved, sources := map[string]string{}, map[string]string{}
		justification := ""
		for _, attribute := range []string{"securityImpactProfile", "class", "multiAgency", "internetReachable"} {
			value, explicit := labelValue(resource.Labels, attribute, selected.Provider == "gcp")
			if explicit {
				resolved[attribute] = value
				sources[attribute] = "tag-override"
				continue
			}
			if attribute != "class" {
				families := []struct {
					name  string
					rules []rule
				}{{"nameRules", selected.NameRules}, {"tagRules", selected.TagRules}, {"networkRules", selected.NetworkRules}, {"typeRules", selected.TypeRules}}
				for _, family := range families {
					for index, r := range family.rules {
						if r.attribute(attribute) == "" {
							continue
						}
						matched, matchErr := r.matches(ref, providerType, resource.Labels, family.name)
						if matchErr != nil {
							return fmt.Errorf("%s: %w", ref.UID, matchErr)
						}
						if matched {
							resolved[attribute] = r.attribute(attribute)
							if attribute == "internetReachable" {
								justification = r.Justification
							}
							sources[attribute] = fmt.Sprintf("scopes[%d].%s[%d]", scopeIndex, family.name, index)
							if attribute == "internetReachable" && r.Reachable == "false" && strings.TrimSpace(r.Justification) == "" {
								return fmt.Errorf("internetReachable false requires internetReachableJustification")
							}
							break
						}
					}
					if resolved[attribute] != "" {
						break
					}
				}
			}
			if resolved[attribute] == "" && selected.attribute(attribute) != "" {
				resolved[attribute] = selected.attribute(attribute)
				if attribute == "internetReachable" {
					justification = selected.Justification
				}
				sources[attribute] = fmt.Sprintf("scopes[%d].%s", scopeIndex, attribute)
			}
			if resolved[attribute] == "" && doc.Defaults.attribute(attribute) != "" {
				resolved[attribute] = doc.Defaults.attribute(attribute)
				sources[attribute] = "defaults." + attribute
			}
		}
		if !config.ValidCloudProfile(resolved["securityImpactProfile"]) {
			return fmt.Errorf("%s: missing or invalid securityImpactProfile", ref.UID)
		}
		class := strings.ToUpper(resolved["class"])
		if class != "A" && class != "B" && class != "C" && class != "D" {
			return fmt.Errorf("%s: missing or invalid class", ref.UID)
		}
		multi := resolved["multiAgency"]
		if multi != "true" && multi != "false" {
			return fmt.Errorf("%s: missing or invalid multiAgency", ref.UID)
		}
		if resource.Labels == nil {
			resource.Labels = map[string]string{}
		}
		resource.Labels[config.LabelKeys.SecurityImpactProfile] = resolved["securityImpactProfile"]
		resource.Labels[config.LabelKeys.Class] = class
		resource.Labels[config.LabelKeys.MultiAgency] = multi
		resource.ClassificationSources = map[string]string{}
		for key, source := range sources {
			resource.ClassificationSources[key] = "cloudPolicy:" + source
		}
		if reachable := resolved["internetReachable"]; reachable != "" {
			if reachable == "false" && sources["internetReachable"] != "tag-override" && strings.TrimSpace(justification) == "" {
				return fmt.Errorf("internetReachable false requires internetReachableJustification")
			}
			if reachable != "true" && reachable != "false" {
				return fmt.Errorf("invalid internetReachable value")
			}
			attest := func(asset model.ResourceRef) {
				exposure := exposures[asset]
				exposure.InternetAccessible = reachable == "true"
				exposure.Provider = "cloud-policy"
				exposure.AssessmentBasis = "attested"
				exposure.Evidence = append(exposure.Evidence, "cloud policy sha256: "+evidence.SHA256, "assignment: "+sources["internetReachable"])
				if justification != "" {
					exposure.Evidence = append(exposure.Evidence, "justification: "+justification)
				}
				exposures[asset] = exposure
			}
			attest(ref)
			for _, image := range inventory.Images {
				for _, asset := range image.Resources {
					if asset.UID == ref.UID {
						attest(asset)
					}
				}
			}
		}
		multiBool, _ := strconv.ParseBool(multi)
		evidence.Assignments = append(evidence.Assignments, model.CloudPolicyAssignment{ResourceUID: ref.UID, ProviderType: providerType, SecurityImpactProfile: resolved["securityImpactProfile"], Class: class, MultiAgency: multiBool, Sources: sources})
	}
	inventory.CloudPolicy = evidence
	return nil
}
