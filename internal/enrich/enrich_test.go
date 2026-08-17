package enrich

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
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

	enriched, warnings, err := EnrichFindings(context.Background(), findings, epssStore, vulnrichmentStore)
	if err != nil {
		t.Fatalf("EnrichFindings returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
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

	enriched, warnings, err := EnrichFindings(context.Background(), findings, nil, vulnrichmentStore)
	if err != nil {
		t.Fatalf("EnrichFindings returned error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if enriched[0].Vulnrichment != nil {
		t.Fatalf("Vulnrichment = %+v, want nil", enriched[0].Vulnrichment)
	}
}

func TestEnrichFindingsCapturesVulnrichmentErrorAsWarningAndContinues(t *testing.T) {
	findings := []model.Finding{
		{ID: "CVE-2026-0001", Severity: "HIGH"},
		{ID: "CVE-2026-0002", Severity: "LOW"},
	}
	vulnrichmentStore := fakeVulnrichmentStore{
		errors: map[string]error{
			"CVE-2026-0001": errors.New("502 bad gateway"),
		},
		values: map[string]model.Vulnrichment{
			"CVE-2026-0002": {Exploitation: "poc"},
		},
	}

	enriched, warnings, err := EnrichFindings(context.Background(), findings, nil, vulnrichmentStore)
	if err != nil {
		t.Fatalf("EnrichFindings returned unexpected error: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings length = %d, want 1", len(warnings))
	}
	if warnings[0].CVEID != "CVE-2026-0001" || warnings[0].Source != "Vulnrichment" {
		t.Errorf("warning = %+v, want Vulnrichment CVE-2026-0001", warnings[0])
	}
	if enriched[0].Vulnrichment != nil {
		t.Errorf("first finding Vulnrichment = %+v, want nil", enriched[0].Vulnrichment)
	}
	if enriched[1].Vulnrichment == nil || enriched[1].Vulnrichment.Exploitation != "poc" {
		t.Errorf("second finding Vulnrichment = %+v, want 'poc'", enriched[1].Vulnrichment)
	}
}

func TestEnrichFindingsEPSSFailsOnceAndDisablesForRemainder(t *testing.T) {
	findings := []model.Finding{
		{ID: "CVE-2026-0001"},
		{ID: "CVE-2026-0002"},
		{ID: "CVE-2026-0003"},
	}
	epssCalls := 0
	epssStore := countingEPSSStore{
		onLookup: func() (model.EPSS, bool, error) {
			epssCalls++
			return model.EPSS{}, false, errors.New("network unreachable")
		},
	}

	enriched, warnings, err := EnrichFindings(context.Background(), findings, epssStore, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings length = %d, want 1", len(warnings))
	}
	if warnings[0].Source != "EPSS" {
		t.Errorf("warning Source = %q, want 'EPSS'", warnings[0].Source)
	}
	if epssCalls != 1 {
		t.Errorf("epssCalls = %d, want exactly 1 (store disabled after first failure)", epssCalls)
	}
	if len(enriched) != 3 {
		t.Errorf("enriched length = %d, want 3", len(enriched))
	}
}

func TestEnrichFindingsCapsVulnrichmentWarningsAtFivePlusRollup(t *testing.T) {
	var findings []model.Finding
	errs := make(map[string]error)
	for i := 1; i <= 10; i++ {
		cve := fmt.Sprintf("CVE-2026-%04d", i)
		findings = append(findings, model.Finding{ID: cve})
		errs[cve] = errors.New("502 bad gateway")
	}

	vulnrichmentStore := fakeVulnrichmentStore{errors: errs}

	enriched, warnings, err := EnrichFindings(context.Background(), findings, nil, vulnrichmentStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(enriched) != 10 {
		t.Errorf("enriched length = %d, want 10", len(enriched))
	}
	// 5 individual warnings + 1 rollup warning = 6 warnings
	if len(warnings) != 6 {
		t.Fatalf("warnings count = %d, want 6 (5 individual + 1 rollup)", len(warnings))
	}
	for i := 0; i < 5; i++ {
		if warnings[i].CVEID == "" {
			t.Errorf("warning[%d] missing CVEID: %+v", i, warnings[i])
		}
	}
	if warnings[5].CVEID != "" {
		t.Errorf("rollup warning should not have CVEID: %+v", warnings[5])
	}
	if warnings[5].Message != "5 additional CVE lookup failures suppressed" {
		t.Errorf("rollup message = %q, want '5 additional CVE lookup failures suppressed'", warnings[5].Message)
	}
}

func TestEnrichFindingsHandlesCircuitBreakerTrip(t *testing.T) {
	findings := []model.Finding{
		{ID: "CVE-2026-0001"},
		{ID: "CVE-2026-0002"},
	}
	vulnrichmentStore := fakeVulnrichmentStore{
		errors: map[string]error{
			"CVE-2026-0001": ErrSourceUnavailable,
			"CVE-2026-0002": ErrSourceUnavailable,
		},
	}

	_, warnings, err := EnrichFindings(context.Background(), findings, nil, vulnrichmentStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Exactly 1 warning for circuit breaker trip across all findings
	if len(warnings) != 1 {
		t.Fatalf("warnings count = %d, want 1", len(warnings))
	}
	if warnings[0].Source != "Vulnrichment" {
		t.Errorf("warning source = %q, want 'Vulnrichment'", warnings[0].Source)
	}
}

func TestEnrichFindingsContextCancellationReturnsPartialFindingsAndError(t *testing.T) {
	// 1. Context canceled before loop
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := []model.Finding{
		{ID: "CVE-2026-0001"},
		{ID: "CVE-2026-0002"},
	}

	enriched, _, err := EnrichFindings(ctx, findings, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(enriched) != 2 {
		t.Errorf("enriched findings length = %d, want 2", len(enriched))
	}

	// 2. Cancellation returned by EPSS store on second finding: finding 0 has EPSS enriched
	epssStore := fakeEPSSStore{
		values: map[string]model.EPSS{
			"CVE-2026-0001": {Score: 0.88},
		},
		errors: map[string]error{
			"CVE-2026-0002": context.Canceled,
		},
	}
	enrichedEPSS, _, errEPSS := EnrichFindings(context.Background(), findings, epssStore, nil)
	if !errors.Is(errEPSS, context.Canceled) {
		t.Fatalf("expected context.Canceled from EPSS store, got %v", errEPSS)
	}
	if enrichedEPSS[0].EPSS == nil || enrichedEPSS[0].EPSS.Score != 0.88 {
		t.Errorf("first finding should have kept EPSS enrichment, got %+v", enrichedEPSS[0].EPSS)
	}
	if enrichedEPSS[1].EPSS != nil {
		t.Errorf("second finding should not have EPSS enrichment, got %+v", enrichedEPSS[1].EPSS)
	}

	// 3. Cancellation returned by Vulnrichment store on second finding: finding 0 has Vulnrichment enriched
	vulnStore := fakeVulnrichmentStore{
		values: map[string]model.Vulnrichment{
			"CVE-2026-0001": {Exploitation: "active"},
		},
		errors: map[string]error{
			"CVE-2026-0002": context.Canceled,
		},
	}
	enrichedVuln, _, errVuln := EnrichFindings(context.Background(), findings, nil, vulnStore)
	if !errors.Is(errVuln, context.Canceled) {
		t.Fatalf("expected context.Canceled from Vulnrichment store, got %v", errVuln)
	}
	if enrichedVuln[0].Vulnrichment == nil || enrichedVuln[0].Vulnrichment.Exploitation != "active" {
		t.Errorf("first finding should have kept Vulnrichment enrichment, got %+v", enrichedVuln[0].Vulnrichment)
	}
	if enrichedVuln[1].Vulnrichment != nil {
		t.Errorf("second finding should not have Vulnrichment enrichment, got %+v", enrichedVuln[1].Vulnrichment)
	}
}

type fakeEPSSStore struct {
	values map[string]model.EPSS
	errors map[string]error
	err    error
}

func (s fakeEPSSStore) LookupContext(ctx context.Context, cveID string) (model.EPSS, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.EPSS{}, false, err
	}
	if s.err != nil {
		return model.EPSS{}, false, s.err
	}
	if s.errors != nil {
		if err, ok := s.errors[cveID]; ok {
			return model.EPSS{}, false, err
		}
	}
	value, ok := s.values[cveID]
	return value, ok, nil
}

type countingEPSSStore struct {
	onLookup func() (model.EPSS, bool, error)
}

func (s countingEPSSStore) LookupContext(ctx context.Context, cveID string) (model.EPSS, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.EPSS{}, false, err
	}
	return s.onLookup()
}

type fakeVulnrichmentStore struct {
	values     map[string]model.Vulnrichment
	errors     map[string]error
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
	if s.errors != nil {
		if err, ok := s.errors[cveID]; ok {
			return model.Vulnrichment{}, false, err
		}
	}
	if s.missingErr != nil {
		return model.Vulnrichment{}, false, s.missingErr
	}
	value, ok := s.values[cveID]
	return value, ok, nil
}
