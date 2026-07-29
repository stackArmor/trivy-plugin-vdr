package main

import (
	"testing"
)

func TestBuildCatalogFiltersAndNormalizesRelationships(t *testing.T) {
	capec := []byte(`<?xml version="1.0"?>
	<Attack_Pattern_Catalog Version="test-capec" Date="2026-07-28">
	  <Attack_Patterns>
	    <Attack_Pattern ID="1" Name="Source" Abstraction="Standard" Status="Stable">
	      <Related_Attack_Patterns>
	        <Related_Attack_Pattern Nature="CanPrecede" CAPEC_ID="2"/>
	      </Related_Attack_Patterns>
	      <Consequences>
	        <Consequence><Scope>Integrity</Scope><Impact>Execute Unauthorized Commands</Impact></Consequence>
	      </Consequences>
	      <Prerequisites><Prerequisite>Attacker controls <b>input</b>.</Prerequisite></Prerequisites>
	      <Related_Weaknesses><Related_Weakness CWE_ID="94"/></Related_Weaknesses>
	      <Taxonomy_Mappings>
	        <Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>1059</Entry_ID><Entry_Name>Old name</Entry_Name></Taxonomy_Mapping>
	      </Taxonomy_Mappings>
	    </Attack_Pattern>
	    <Attack_Pattern ID="2" Name="Target" Abstraction="Detailed" Status="Draft">
	      <Related_Attack_Patterns>
	        <Related_Attack_Pattern Nature="CanFollow" CAPEC_ID="1"/>
	      </Related_Attack_Patterns>
	      <Related_Weaknesses><Related_Weakness CWE_ID="269"/></Related_Weaknesses>
	    </Attack_Pattern>
	    <Attack_Pattern ID="3" Name="Too broad" Abstraction="Meta" Status="Stable">
	      <Related_Weaknesses><Related_Weakness CWE_ID="20"/></Related_Weaknesses>
	    </Attack_Pattern>
	    <Attack_Pattern ID="4" Name="Old" Abstraction="Standard" Status="Deprecated">
	      <Related_Weaknesses><Related_Weakness CWE_ID="79"/></Related_Weaknesses>
	    </Attack_Pattern>
	  </Attack_Patterns>
	</Attack_Pattern_Catalog>`)
	attack := []byte(`{
	  "type":"bundle",
	  "objects":[
	    {
	      "type":"x-mitre-collection",
	      "name":"Enterprise ATT&CK",
	      "x_mitre_version":"test-attack",
	      "modified":"2026-07-28T00:00:00Z"
	    },
	    {
	      "type":"attack-pattern",
	      "name":"Command and Scripting Interpreter",
	      "external_references":[{"source_name":"mitre-attack","external_id":"T1059"}],
	      "kill_chain_phases":[{"phase_name":"execution"}]
	    }
	  ]
	}`)

	data, stats, err := buildCatalog(capec, attack)
	if err != nil {
		t.Fatalf("buildCatalog returned error: %v", err)
	}
	if stats.Patterns != 2 || stats.CWEs != 2 || stats.ATTACKMappings != 1 || stats.ChainEdges != 1 {
		t.Fatalf("stats = %#v, want 2 patterns/2 CWEs/1 mapping/1 edge", stats)
	}
	source := data.Patterns["CAPEC-1"]
	target := data.Patterns["CAPEC-2"]
	if len(source.Successors) != 1 || source.Successors[0] != "CAPEC-2" {
		t.Fatalf("source successors = %v, want CAPEC-2", source.Successors)
	}
	if len(target.Predecessors) != 1 || target.Predecessors[0] != "CAPEC-1" {
		t.Fatalf("target predecessors = %v, want CAPEC-1", target.Predecessors)
	}
	if len(source.Techniques) != 1 || source.Techniques[0].ID != "T1059" || source.Techniques[0].Name != "Command and Scripting Interpreter" {
		t.Fatalf("source techniques = %#v, want resolved T1059", source.Techniques)
	}
	if len(source.Prerequisites) != 1 || source.Prerequisites[0] != "Attacker controls input." {
		t.Fatalf("source prerequisites = %#v, want cleaned structured text", source.Prerequisites)
	}
	if _, ok := data.Patterns["CAPEC-3"]; ok {
		t.Fatal("Meta CAPEC-3 was not filtered")
	}
	if _, ok := data.Patterns["CAPEC-4"]; ok {
		t.Fatal("deprecated CAPEC-4 was not filtered")
	}
}
