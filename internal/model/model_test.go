package model

import (
	"encoding/json"
	"testing"
)

func TestAccessProtectionJSONUsesAuthProxyFieldNames(t *testing.T) {
	data, err := json.Marshal(AccessProtection{
		Type:    "iap",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("marshal AccessProtection: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("unmarshal AccessProtection JSON: %v", err)
	}

	if got := output["authProxyType"]; got != "iap" {
		t.Fatalf("authProxyType = %#v, want %q", got, "iap")
	}
	if got := output["authProxyEnabled"]; got != true {
		t.Fatalf("authProxyEnabled = %#v, want true", got)
	}
	for _, legacyField := range []string{"type", "enabled"} {
		if _, ok := output[legacyField]; ok {
			t.Fatalf("legacy field %q is present in AccessProtection JSON: %s", legacyField, data)
		}
	}
}

func TestFindingJSONPreservesSourceKeyedCVSS(t *testing.T) {
	v3Score := 9.8
	v40Score := 8.7
	finding := Finding{
		ID:         "CVE-2026-0001",
		ImageRef:   "example/app:v1",
		Severity:   "HIGH",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSS: map[string]CVSSInfo{
			"nvd": {
				V3Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				V3Score:   &v3Score,
				V40Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				V40Score:  &v40Score,
			},
		},
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal Finding: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("unmarshal Finding JSON: %v", err)
	}
	if output["cvssVector"] != finding.CVSSVector {
		t.Fatalf("cvssVector = %#v, want unchanged selected baseline", output["cvssVector"])
	}
	cvss, ok := output["cvss"].(map[string]any)
	if !ok {
		t.Fatalf("cvss = %#v, want source-keyed object", output["cvss"])
	}
	nvd, ok := cvss["nvd"].(map[string]any)
	if !ok || nvd["V3Score"] != 9.8 || nvd["V40Score"] != 8.7 {
		t.Fatalf("cvss.nvd = %#v, want versioned vectors and scores", cvss["nvd"])
	}
}
