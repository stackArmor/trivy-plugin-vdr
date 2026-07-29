package chaincatalog

import (
	"testing"
)

func TestParseAndLookupPatternsForCWEs(t *testing.T) {
	raw := []byte(`{
		"schemaVersion":"1",
		"sources":{
			"capecVersion":"test",
			"capecSha256":"capec",
			"attackVersion":"test",
			"attackSha256":"attack"
		},
		"patterns":{
			"CAPEC-1":{"id":"CAPEC-1","name":"One","abstraction":"Standard","status":"Stable","cwes":["CWE-94"]},
			"CAPEC-2":{"id":"CAPEC-2","name":"Two","abstraction":"Detailed","status":"Draft","cwes":["CWE-94","CWE-95"]}
		},
		"cwes":{
			"CWE-94":["CAPEC-1","CAPEC-2"],
			"CWE-95":["CAPEC-2"]
		}
	}`)

	catalog, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	patterns := catalog.PatternsForCWEs([]string{"cwe-95", " CWE-94 "})
	if len(patterns) != 2 || patterns[0].ID != "CAPEC-1" || patterns[1].ID != "CAPEC-2" {
		t.Fatalf("PatternsForCWEs = %#v, want CAPEC-1 and CAPEC-2", patterns)
	}
	if pattern, ok := catalog.Pattern("2"); !ok || pattern.ID != "CAPEC-2" {
		t.Fatalf("Pattern(2) = %#v, %v; want CAPEC-2", pattern, ok)
	}
}

func TestParseRejectsDanglingCWEPatternReference(t *testing.T) {
	raw := []byte(`{
		"schemaVersion":"1",
		"sources":{
			"capecVersion":"test",
			"capecSha256":"capec",
			"attackVersion":"test",
			"attackSha256":"attack"
		},
		"patterns":{},
		"cwes":{"CWE-94":["CAPEC-404"]}
	}`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("Parse returned nil error for dangling CAPEC reference")
	}
}

func TestParseRejectsOneSidedChainEdge(t *testing.T) {
	raw := []byte(`{
		"schemaVersion":"1",
		"sources":{
			"capecVersion":"test",
			"capecSha256":"capec",
			"attackVersion":"test",
			"attackSha256":"attack"
		},
		"patterns":{
			"CAPEC-1":{"id":"CAPEC-1","name":"One","abstraction":"Standard","status":"Stable","successors":["CAPEC-2"]},
			"CAPEC-2":{"id":"CAPEC-2","name":"Two","abstraction":"Detailed","status":"Draft"}
		},
		"cwes":{}
	}`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("Parse returned nil error for one-sided CAPEC edge")
	}
}

func TestBuiltinCatalogCarriesPinnedCorpusProvenance(t *testing.T) {
	catalog, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin returned error: %v", err)
	}
	sources := catalog.Sources()
	if sources.CAPECVersion != "3.9" || sources.ATTACKVersion != "19.1" {
		t.Fatalf("Sources = %#v, want CAPEC 3.9 and ATT&CK 19.1", sources)
	}
	if sources.CAPECSHA256 == "" || sources.ATTACKSHA256 == "" {
		t.Fatalf("Sources = %#v, want source hashes", sources)
	}
	if patterns := catalog.PatternsForCWEs([]string{"CWE-94"}); len(patterns) == 0 {
		t.Fatal("builtin catalog has no CWE-94 paths")
	}
}
