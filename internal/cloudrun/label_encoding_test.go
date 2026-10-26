package cloudrun

import "testing"

func TestGCPVDRLabelsAreDecodedForStandaloneScoring(t *testing.T) {
	raw := map[string]string{"vdr_fedramp_io_security_impact_profile": "public-content__bounded-processing__bounded-service", "vdr_fedramp_io_class": "d"}
	labels := copyStringMap(raw)
	if labels["vdr.fedramp.io/security-impact-profile"] != "public-content.bounded-processing.bounded-service" {
		t.Fatalf("labels=%#v", labels)
	}
	if _, exists := raw["vdr.fedramp.io/class"]; exists {
		t.Fatal("decoder modified API response")
	}
}
