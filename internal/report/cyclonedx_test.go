package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func sampleCycloneDXReport() model.Report {
	automount := false
	replicas := int32(3)
	published := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	modified := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	return model.Report{
		GeneratedAt: time.Date(2026, 6, 28, 14, 0, 0, 0, time.UTC),
		ContextName: "prod-cluster",
		Class:       "B",
		Resources: []model.ResourceReport{
			{
				Resource: model.ResourceRef{
					Kind:          "Deployment",
					Namespace:     "default",
					Name:          "payments-api",
					ContainerName: "app",
				},
				Images: []model.ContainerImage{{Name: "app", ImageRef: "registry.example.com/payments-api:2.4.1"}},
				Exposure: &model.Exposure{
					InternetAccessible: true,
					Evidence:           []string{"HTTPRoute public/payments -> Service default/payments-api:8080"},
					Routes: []model.RouteMetadata{{
						BackendProtocol:        "http",
						BackendProtocolVersion: "HTTP2",
						ALPN:                   []string{"h2"},
					}},
				},
				Posture: &model.WorkloadPosture{
					SecurityContext: &model.PostureSecurityContext{
						RunAsNonRoot:        true,
						DroppedCapabilities: []string{"ALL"},
					},
					Workload: &model.PostureWorkload{Replicas: &replicas, ReadinessProbe: true},
					Identity: &model.PostureIdentity{
						ServiceAccountName:           "payments",
						AutomountServiceAccountToken: &automount,
					},
					NetworkPolicy: &model.PostureNetworkPolicy{
						SelectedByEgressPolicy: true,
						EgressAllowedCIDRs:     []string{"10.0.0.0/8"},
					},
				},
				Findings: []model.Finding{
					{
						ID:                  "CVE-2026-30303",
						ImageRef:            "registry.example.com/payments-api:2.4.1",
						Target:              "/usr/bin/payments-api",
						TargetClass:         "lang-pkgs",
						TargetType:          "gobinary",
						PackageID:           "libssl@3.2.1-r0",
						PackageName:         "libssl",
						PackagePURL:         "pkg:apk/wolfi/libssl@3.2.1-r0",
						PackageUID:          "libssl@3.2.1-r0",
						PackagePath:         "/usr/lib/libssl.so",
						PackageRelationship: "direct",
						Severity:            "HIGH",
						SeveritySource:      "wolfi",
						VendorSeverity:      map[string]string{"nvd": "CRITICAL", "wolfi": "HIGH"},
						DataSource:          &model.VulnerabilityDataSource{ID: "wolfi", Name: "Wolfi SecDB", URL: "https://packages.wolfi.dev/os/security.json", BaseID: "osv"},
						PrimaryURL:          "https://avd.aquasec.com/nvd/cve-2026-30303",
						ScannerFingerprint:  "sha256:scanner-fingerprint",
						VendorIDs:           []string{"GHSA-abcd-1234-5678", "WOLFI-2026-30303"},
						PublishedDate:       &published,
						LastModifiedDate:    &modified,
						CVSSVector:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						CWEs:                []string{"CWE-787", "CWE-79"},
						Pain:                &model.Pain{Tier: "N4", Word: "Debilitating", Archetype: "web-service"},
						Remediation:         &model.Remediation{Column: "LEV+IRV", LEV: true, IRV: true, DeadlineDays: 3},
					},
				},
			},
		},
		SuppressedFindings: []model.Finding{
			{
				ID:          "CVE-2026-10101",
				ImageRef:    "registry.example.com/payments-api:2.4.1",
				PackageName: "parser",
				Severity:    "CRITICAL",
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Suppressed:  true,
				Suppression: &model.Suppression{
					Source:        "vex",
					Status:        "not_affected",
					Justification: "code_not_reachable",
				},
				WouldHaveBeenPain:        &model.Pain{Tier: "N5", Word: "Debilitating", Archetype: "web-service"},
				WouldHaveBeenRemediation: &model.Remediation{Column: "LEV+IRV", LEV: true, IRV: true, DeadlineDays: 1},
				Affected: []model.Affected{{
					Resource: model.ResourceRef{
						Kind:          "Deployment",
						Namespace:     "default",
						Name:          "payments-api",
						ContainerName: "app",
					},
					Exposure: &model.Exposure{InternetAccessible: true},
				}},
			},
		},
	}
}

func TestToCycloneDXStructure(t *testing.T) {
	doc := ToCycloneDX(sampleCycloneDXReport())

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", doc.SpecVersion)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if doc.Metadata == nil || doc.Metadata.Tools == nil || len(doc.Metadata.Tools.Components) == 0 {
		t.Fatalf("metadata.tools.components missing")
	}
	if got := doc.Metadata.Tools.Components[0].Name; got != "trivy-plugin-vdr" {
		t.Errorf("tool name = %q, want trivy-plugin-vdr", got)
	}
	if doc.Metadata.Timestamp != "2026-06-28T14:00:00Z" {
		t.Errorf("timestamp = %q, want 2026-06-28T14:00:00Z", doc.Metadata.Timestamp)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(doc.Components))
	}
}

func TestToCycloneDXOneVulnPerCVEAsset(t *testing.T) {
	doc := ToCycloneDX(sampleCycloneDXReport())

	// One active + one suppressed finding, each on the same single asset.
	if len(doc.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %d, want 2", len(doc.Vulnerabilities))
	}
	seen := map[string]int{}
	assetRef := assetBOMRef(model.ResourceRef{Kind: "Deployment", Namespace: "default", Name: "payments-api", ContainerName: "app"})
	for _, v := range doc.Vulnerabilities {
		if len(v.Affects) != 1 {
			t.Fatalf("vuln %s: affects = %d, want 1", v.ID, len(v.Affects))
		}
		if v.Affects[0].Ref != assetRef {
			t.Errorf("vuln %s: affects ref = %q, want %q", v.ID, v.Affects[0].Ref, assetRef)
		}
		key := v.ID + "|" + v.Affects[0].Ref
		seen[key]++
		if seen[key] > 1 {
			t.Errorf("duplicate (CVE, asset) pair: %s", key)
		}
	}
}

func TestToCycloneDXAnalysisMapping(t *testing.T) {
	doc := ToCycloneDX(sampleCycloneDXReport())

	active := findVuln(t, doc, "CVE-2026-30303")
	if active.Analysis == nil || active.Analysis.State != "exploitable" {
		t.Errorf("active analysis state = %+v, want exploitable", active.Analysis)
	}

	suppressed := findVuln(t, doc, "CVE-2026-10101")
	if suppressed.Analysis == nil {
		t.Fatal("suppressed vuln has no analysis")
	}
	if suppressed.Analysis.State != "not_affected" {
		t.Errorf("suppressed state = %q, want not_affected", suppressed.Analysis.State)
	}
	if suppressed.Analysis.Justification != "code_not_reachable" {
		t.Errorf("suppressed justification = %q, want code_not_reachable", suppressed.Analysis.Justification)
	}
}

func TestToCycloneDXVDRProperties(t *testing.T) {
	doc := ToCycloneDX(sampleCycloneDXReport())

	comp := doc.Components[0]
	compProps := propMap(comp.Properties)
	wantAsset := map[string]string{
		"vdr:assetInternetReachable":                        "true",
		"vdr:exposedBackendProtocol":                        "http",
		"vdr:exposedBackendProtocolVersion":                 "HTTP2",
		"vdr:exposedBackendAlpn":                            "h2",
		"vdr:posture:securityContext:runAsNonRoot":          "true",
		"vdr:posture:workload:replicas":                     "3",
		"vdr:posture:identity:serviceAccountName":           "payments",
		"vdr:posture:networkPolicy:egressAllowedCidrs":      "10.0.0.0/8",
		"vdr:posture:identity:automountServiceAccountToken": "false",
	}
	for k, want := range wantAsset {
		if got := compProps[k]; got != want {
			t.Errorf("component property %s = %q, want %q", k, got, want)
		}
	}
	if _, ok := compProps["vdr:routeEvidence"]; !ok {
		t.Errorf("component missing vdr:routeEvidence")
	}

	active := findVuln(t, doc, "CVE-2026-30303")
	vulnProps := propMap(active.Properties)
	wantVuln := map[string]string{
		"vdr:pain":                        "N4",
		"vdr:cwes":                        "CWE-787,CWE-79",
		"vdr:target":                      "/usr/bin/payments-api",
		"vdr:targetClass":                 "lang-pkgs",
		"vdr:targetType":                  "gobinary",
		"vdr:packageId":                   "libssl@3.2.1-r0",
		"vdr:affectedPackagePurl":         "pkg:apk/wolfi/libssl@3.2.1-r0",
		"vdr:affectedPackageUid":          "libssl@3.2.1-r0",
		"vdr:affectedPackagePath":         "/usr/lib/libssl.so",
		"vdr:affectedPackageRelationship": "direct",
		"vdr:severitySource":              "wolfi",
		"vdr:vendorSeverity":              "nvd=CRITICAL,wolfi=HIGH",
		"vdr:dataSourceId":                "wolfi",
		"vdr:dataSourceName":              "Wolfi SecDB",
		"vdr:dataSourceUrl":               "https://packages.wolfi.dev/os/security.json",
		"vdr:dataSourceBaseId":            "osv",
		"vdr:primaryUrl":                  "https://avd.aquasec.com/nvd/cve-2026-30303",
		"vdr:scannerFingerprint":          "sha256:scanner-fingerprint",
		"vdr:vendorIds":                   "GHSA-abcd-1234-5678,WOLFI-2026-30303",
		"vdr:remediationTrack":            "LEV+IRV",
		"vdr:findingInternetReachable":    "true",
		"vdr:reachabilityDecision":        "insufficient_evidence_to_downgrade",
	}
	for k, want := range wantVuln {
		if got := vulnProps[k]; got != want {
			t.Errorf("vuln property %s = %q, want %q", k, got, want)
		}
	}
	// Numeric cwes array.
	if len(active.CWEs) != 2 || active.CWEs[0] != 79 || active.CWEs[1] != 787 {
		t.Errorf("cwes = %v, want [79 787]", active.CWEs)
	}
	// CVSS rating.
	if len(active.Ratings) != 1 || active.Ratings[0].Method != "CVSSv31" || active.Ratings[0].Severity != "high" {
		t.Errorf("ratings = %+v, want one CVSSv31/high", active.Ratings)
	}
	if active.Ratings[0].Source == nil || active.Ratings[0].Source.Name != "wolfi" {
		t.Errorf("rating source = %+v, want wolfi", active.Ratings[0].Source)
	}
	if active.Source == nil || active.Source.Name != "Wolfi SecDB" || active.Source.URL != "https://packages.wolfi.dev/os/security.json" {
		t.Errorf("vulnerability source = %+v, want Wolfi SecDB", active.Source)
	}
	if active.Published != "2026-01-02T03:04:05Z" || active.Updated != "2026-02-03T04:05:06Z" {
		t.Errorf("published/updated = %q/%q", active.Published, active.Updated)
	}
}

func TestToCycloneDXDeterministic(t *testing.T) {
	var first bytes.Buffer
	if err := RenderCycloneDX(&first, sampleCycloneDXReport()); err != nil {
		t.Fatalf("render: %v", err)
	}
	for i := 0; i < 5; i++ {
		var buf bytes.Buffer
		if err := RenderCycloneDX(&buf, sampleCycloneDXReport()); err != nil {
			t.Fatalf("render: %v", err)
		}
		if !bytes.Equal(first.Bytes(), buf.Bytes()) {
			t.Fatalf("non-deterministic output on iteration %d", i)
		}
	}
}

func TestRenderCycloneDXValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCycloneDX(&buf, sampleCycloneDXReport()); err != nil {
		t.Fatalf("render: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(buf.Bytes(), &generic); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, key := range []string{"bomFormat", "specVersion", "version", "components", "vulnerabilities"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("output missing required key %q", key)
		}
	}
}

func findVuln(t *testing.T, doc cdxDocument, id string) cdxVulnerability {
	t.Helper()
	for _, v := range doc.Vulnerabilities {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vulnerability %q not found", id)
	return cdxVulnerability{}
}

func propMap(props []cdxProperty) map[string]string {
	out := map[string]string{}
	for _, p := range props {
		out[p.Name] = p.Value
	}
	return out
}
