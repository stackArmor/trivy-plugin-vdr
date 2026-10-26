package cloudpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/report"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scoring"
)

type contractCase struct {
	Name, Provider, Account, Region, Kind, UID, ResourceName, Profile, Class string
	Labels                                                                   map[string]string
	MultiAgency                                                              bool
}

func contract(t *testing.T) (string, []contractCase) {
	t.Helper()
	data, err := os.ReadFile("testdata/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Policy string
		Cases  []contractCase
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Policy, fixture.Cases
}

func inventory(c contractCase) *model.Inventory {
	provider := "aws-ecs"
	if c.Provider == "gcp" {
		provider = "gcp-cloud-run"
	}
	return &model.Inventory{Cloud: model.NewCloudContext(c.Provider, c.Account, []string{c.Region}), Resources: []model.ResourceInventory{{Resource: model.ResourceRef{Provider: provider, Project: c.Account, Region: c.Region, Kind: c.Kind, Name: c.ResourceName, UID: c.UID}, Labels: c.Labels}}}
}

func apply(t *testing.T, policy string, inv *model.Inventory, config *scoring.Config) error {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "vdr-cloud.yaml")
	if err := os.WriteFile(filename, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	return Apply(filename, inv, config, map[model.ResourceRef]model.Exposure{})
}

func TestSharedTSWContract(t *testing.T) {
	policy, cases := contract(t)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			inv := inventory(c)
			config := scoring.Default()
			thresholds := config.WordThresholds
			if err := apply(t, policy, inv, config); err != nil {
				t.Fatal(err)
			}
			assignment := inv.CloudPolicy.Assignments[0]
			if assignment.SecurityImpactProfile != c.Profile || assignment.Class != c.Class || assignment.MultiAgency != c.MultiAgency {
				t.Fatalf("assignment=%#v", assignment)
			}
			if len(inv.CloudPolicy.SHA256) != 64 || config.WordThresholds != thresholds {
				t.Fatal("missing policy digest or modified scoring calibration")
			}
			result := config.Score(scoring.Input{Labels: inv.Resources[0].Labels, ClassificationSources: inv.Resources[0].ClassificationSources, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
			if result.SecurityImpactProfile != c.Profile || !strings.HasPrefix(result.SecurityImpactProfileSource, "cloudPolicy:") {
				t.Fatalf("scoring did not use resolved policy: %#v", result)
			}
		})
	}
}

func TestResolvedPolicyReachesTheFinalReport(t *testing.T) {
	policy, cases := contract(t)
	inv := inventory(cases[0])
	config := scoring.Default()
	ref := inv.Resources[0].Resource
	ref.ContainerName = "web"
	ref.ContainerType = "container"
	inv.Resources[0].Images = []model.ContainerImage{{Name: "web", ContainerType: "container", ImageRef: "example/web:v1"}}
	inv.Images = []model.ImageInventory{{ImageRef: "example/web:v1", Resources: []model.ResourceRef{ref}}}
	if err := apply(t, policy, inv, config); err != nil {
		t.Fatal(err)
	}
	result := report.Build(inv, []model.Finding{{ID: "CVE-2026-0001", ImageRef: "example/web:v1", Severity: "HIGH", CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", AffectedResources: []model.ResourceRef{ref}}}, nil, report.Options{Scoring: config, MinEPSS: -1})
	if result.CloudPolicy == nil || len(result.CloudPolicy.Assignments) != 1 {
		t.Fatal("final JSON lost cloud policy provenance")
	}
	if len(result.Findings) != 1 || len(result.Findings[0].Affected) != 1 {
		t.Fatal("finding-to-container association lost")
	}
	affected := result.Findings[0].Affected[0]
	if affected.Pain.SecurityImpactProfile != cases[0].Profile || affected.Remediation.Class != "D" {
		t.Fatalf("wrong final assignment: %#v", affected)
	}
	if !strings.HasPrefix(affected.Pain.SecurityImpactProfileSource, "cloudPolicy:") {
		t.Fatal("final report mislabeled policy as a resource tag")
	}
}

func TestWrongScopeIsAnError(t *testing.T) {
	policy, cases := contract(t)
	inv := inventory(cases[0])
	inv.Cloud.AccountID = "999999999999"
	if err := apply(t, policy, inv, scoring.Default()); err == nil {
		t.Fatal("cross-account policy accepted")
	}
}

func TestApplicableNetworkRuleCannotSilentlyFallThrough(t *testing.T) {
	policy, cases := contract(t)
	policy = strings.Replace(policy, "    nameRules:", "    networkRules:\n      - network: vpc-*\n        securityImpactProfile: cr-l_ir-l_ar-l\n    nameRules:", 1)
	c := cases[0]
	c.ResourceName = "worker:1"
	if err := apply(t, policy, inventory(c), scoring.Default()); err == nil || !strings.Contains(err.Error(), "network facts") {
		t.Fatalf("got %v", err)
	}
}

func TestMalformedBooleanIsRejected(t *testing.T) {
	policy, cases := contract(t)
	policy = strings.Replace(policy, `multiAgency: "false"`, `multiAgency: false`, 1)
	if err := apply(t, policy, inventory(cases[0]), scoring.Default()); err == nil {
		t.Fatal("unquoted boolean accepted")
	}
}

func TestBlankOverrideDoesNotFallThroughToLowerPriorityPolicy(t *testing.T) {
	policy, cases := contract(t)
	c := cases[0]
	c.Labels = map[string]string{"vdr.fedramp.io/security-impact-profile": ""}
	if err := apply(t, policy, inventory(c), scoring.Default()); err == nil {
		t.Fatal("blank explicit override silently fell through")
	}
}

func TestScopeReachabilityAttestationNeedsItsOwnJustification(t *testing.T) {
	policy, cases := contract(t)
	policy = strings.Replace(policy, `    account: "123456789012"`, `    account: "123456789012"`+"\n    internetReachable: \"false\"", 1)
	if err := apply(t, policy, inventory(cases[0]), scoring.Default()); err == nil {
		t.Fatal("unjustified scope reachability accepted")
	}
}
