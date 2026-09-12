package report

import (
	"encoding/json"
	"github.com/stackArmor/trivy-plugin-vdr/internal/exposure"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"testing"
)

func TestCompletedNegativeExposureSurvivesJSONViews(t *testing.T) {
	inv := sampleInventory()
	findings := []model.Finding{sampleFinding("CVE-2026-0001", "HIGH", 0.7)}
	for _, complete := range []bool{false, true} {
		exposures := exposure.Analyze(inv, exposure.Objects{CollectionComplete: complete})
		for _, view := range []string{ViewFindings, ViewResources} {
			built := Build(inv, findings, exposures, Options{View: view})
			data, err := json.Marshal(built)
			if err != nil {
				t.Fatal(err)
			}
			var decoded model.Report
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			var entries []*model.Exposure
			if view == ViewFindings {
				entries = []*model.Exposure{decoded.Assets[0].Exposure, decoded.Findings[0].Affected[0].Exposure}
			} else {
				entries = []*model.Exposure{decoded.Resources[0].Exposure, decoded.Resources[0].Findings[0].Affected[0].Exposure}
			}
			for _, entry := range entries {
				if !complete {
					if entry != nil {
						t.Fatalf("missing assessment invented: %#v", entry)
					}
					continue
				}
				if entry == nil || entry.InternetAccessible || entry.AssessmentStatus != "assessed" || len(entry.Evidence) == 0 {
					t.Fatalf("explicit negative lost in %s JSON: %s", view, data)
				}
			}
		}
	}
}
