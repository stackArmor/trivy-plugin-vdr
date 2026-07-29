package chainanalysis

import (
	"reflect"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/chaincatalog"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestClassifyTaxonomyRolesAndPaths(t *testing.T) {
	catalog := testCatalog(t)
	tests := []struct {
		name          string
		cwes          []string
		wantStatus    string
		wantRole      string
		wantAmbiguity string
		wantPred      string
		wantSucc      string
		wantReasons   []string
	}{
		{
			name:          "producer",
			cwes:          []string{"CWE-94"},
			wantStatus:    StatusMapped,
			wantRole:      RoleProducer,
			wantAmbiguity: "none",
			wantPred:      RelationNotDeclared,
			wantSucc:      RelationPresent,
			wantReasons:   []string{"capec-mapped", "attack-technique-mapped", "explicit-capec-successor"},
		},
		{
			name:          "consumer",
			cwes:          []string{"CWE-269"},
			wantStatus:    StatusMapped,
			wantRole:      RoleConsumer,
			wantAmbiguity: "none",
			wantPred:      RelationPresent,
			wantSucc:      RelationNotDeclared,
			wantReasons:   []string{"capec-mapped", "explicit-capec-predecessor"},
		},
		{
			name:          "mixed paths become bridge",
			cwes:          []string{"CWE-94", "CWE-269"},
			wantStatus:    StatusMapped,
			wantRole:      RoleBridge,
			wantAmbiguity: "mixed_roles",
			wantPred:      RelationPresent,
			wantSucc:      RelationPresent,
			wantReasons: []string{
				"capec-mapped",
				"attack-technique-mapped",
				"explicit-capec-predecessor",
				"explicit-capec-successor",
				"multiple-capec-paths",
				"mixed-capec-roles",
			},
		},
		{
			name:          "no CWE is unknown",
			wantStatus:    StatusUnknown,
			wantRole:      RoleUnknown,
			wantAmbiguity: "none",
			wantPred:      RelationUnknown,
			wantSucc:      RelationUnknown,
			wantReasons:   []string{"no-specific-cwe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyTaxonomy(model.Finding{CWEs: tt.cwes}, catalog)
			if got.Status != tt.wantStatus || got.TaxonomyRole != tt.wantRole || got.Ambiguity != tt.wantAmbiguity ||
				got.PredecessorStatus != tt.wantPred || got.SuccessorStatus != tt.wantSucc {
				t.Fatalf("ClassifyTaxonomy = %#v", got)
			}
			if !reflect.DeepEqual(got.ReasonCodes, tt.wantReasons) {
				t.Fatalf("ReasonCodes = %v, want %v", got.ReasonCodes, tt.wantReasons)
			}
		})
	}
}

func TestClassifyTaxonomyPreservesPathEvidence(t *testing.T) {
	got := ClassifyTaxonomy(model.Finding{CWEs: []string{"cwe-94"}}, testCatalog(t))
	if len(got.Paths) != 1 {
		t.Fatalf("Paths = %#v, want one path", got.Paths)
	}
	path := got.Paths[0]
	if path.CWEID != "CWE-94" || path.CAPECID != "CAPEC-1" || path.CAPECName != "Code Pattern" {
		t.Fatalf("Path = %#v, want CWE-94 -> CAPEC-1", path)
	}
	if len(path.ATTACKTechniques) != 1 || path.ATTACKTechniques[0].ID != "T1059" {
		t.Fatalf("ATTACKTechniques = %#v, want T1059", path.ATTACKTechniques)
	}
	if !reflect.DeepEqual(path.ConsequenceImpacts, []string{"Execute Unauthorized Commands"}) {
		t.Fatalf("ConsequenceImpacts = %v", path.ConsequenceImpacts)
	}
}

func testCatalog(t *testing.T) *chaincatalog.Catalog {
	t.Helper()
	raw := []byte(`{
		"schemaVersion":"1",
		"sources":{
			"capecVersion":"test",
			"capecSha256":"capec",
			"attackVersion":"test",
			"attackSha256":"attack"
		},
		"patterns":{
			"CAPEC-1":{
				"id":"CAPEC-1",
				"name":"Code Pattern",
				"abstraction":"Standard",
				"status":"Stable",
				"cwes":["CWE-94"],
				"techniques":[{"id":"T1059","name":"Command and Scripting Interpreter","tactics":["execution"]}],
				"successors":["CAPEC-2"],
				"consequences":[{"impact":"Execute Unauthorized Commands"}]
			},
			"CAPEC-2":{
				"id":"CAPEC-2",
				"name":"Privilege Pattern",
				"abstraction":"Detailed",
				"status":"Draft",
				"cwes":["CWE-269"],
				"predecessors":["CAPEC-1"],
				"consequences":[{"impact":"Gain Privileges"}]
			}
		},
		"cwes":{
			"CWE-94":["CAPEC-1"],
			"CWE-269":["CAPEC-2"]
		}
	}`)
	catalog, err := chaincatalog.Parse(raw)
	if err != nil {
		t.Fatalf("parse test catalog: %v", err)
	}
	return catalog
}
