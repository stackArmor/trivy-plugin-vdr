package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/matthewvenne/trivy-plugin-vdr/internal/model"
)

func TestEnrichFindingsCombinesEPSSAndVulnrichment(t *testing.T) {
	findings := []model.Finding{
		{ID: "CVE-2026-0001", ImageRef: "repo/app:1", Severity: "HIGH"},
		{ID: "CVE-2026-0002", ImageRef: "repo/app:1", Severity: "LOW"},
	}
	epssStore := fakeEPSSStore{
		values: map[string]model.EPSS{
			"CVE-2026-0001": {Score: 0.75, Percentile: 0.95},
		},
	}
	vulnrichmentStore := fakeVulnrichmentStore{
		values: map[string]model.Vulnrichment{
			"CVE-2026-0001": {Exploitation: "active"},
		},
	}

	enriched, err := EnrichFindings(context.Background(), findings, epssStore, vulnrichmentStore)
	if err != nil {
		t.Fatalf("EnrichFindings returned error: %v", err)
	}
	if enriched[0].EPSS == nil || enriched[0].EPSS.Score != 0.75 {
		t.Fatalf("first EPSS = %+v, want score 0.75", enriched[0].EPSS)
	}
	if enriched[0].Vulnrichment == nil || enriched[0].Vulnrichment.Exploitation != "active" {
		t.Fatalf("first Vulnrichment = %+v, want active exploitation", enriched[0].Vulnrichment)
	}
	if enriched[0].ImageRef != findings[0].ImageRef || enriched[0].Severity != findings[0].Severity {
		t.Fatalf("finding fields were not preserved: %+v", enriched[0])
	}
	if enriched[1].EPSS != nil || enriched[1].Vulnrichment != nil {
		t.Fatalf("second finding enrichments = %+v %+v, want nil pointers", enriched[1].EPSS, enriched[1].Vulnrichment)
	}
}

func TestEnrichFindingsDoesNotFailWhenVulnrichmentIsMissing(t *testing.T) {
	findings := []model.Finding{{ID: "CVE-2026-0001", Severity: "HIGH"}}
	vulnrichmentStore := fakeVulnrichmentStore{missingErr: ErrNotFound}

	enriched, err := EnrichFindings(context.Background(), findings, nil, vulnrichmentStore)
	if err != nil {
		t.Fatalf("EnrichFindings returned error: %v", err)
	}
	if enriched[0].Vulnrichment != nil {
		t.Fatalf("Vulnrichment = %+v, want nil", enriched[0].Vulnrichment)
	}
}

type fakeEPSSStore struct {
	values map[string]model.EPSS
	err    error
}

func (s fakeEPSSStore) LookupContext(ctx context.Context, cveID string) (model.EPSS, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.EPSS{}, false, err
	}
	if s.err != nil {
		return model.EPSS{}, false, s.err
	}
	value, ok := s.values[cveID]
	return value, ok, nil
}

type fakeVulnrichmentStore struct {
	values     map[string]model.Vulnrichment
	missingErr error
	err        error
}

func (s fakeVulnrichmentStore) LookupContext(ctx context.Context, cveID string) (model.Vulnrichment, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.Vulnrichment{}, false, err
	}
	if s.err != nil {
		return model.Vulnrichment{}, false, s.err
	}
	if s.missingErr != nil {
		return model.Vulnrichment{}, false, s.missingErr
	}
	value, ok := s.values[cveID]
	return value, ok, nil
}

func TestEnrichFindingsReturnsUnexpectedVulnrichmentErrors(t *testing.T) {
	wantErr := errors.New("server unavailable")
	_, err := EnrichFindings(context.Background(), []model.Finding{{ID: "CVE-2026-0001"}}, nil, fakeVulnrichmentStore{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}
