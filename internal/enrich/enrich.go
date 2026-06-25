package enrich

import (
	"context"
	"errors"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/model"
)

var ErrNotFound = errors.New("enrichment not found")

type EPSSStore interface {
	LookupContext(ctx context.Context, cveID string) (model.EPSS, bool, error)
}

type VulnrichmentStore interface {
	LookupContext(ctx context.Context, cveID string) (model.Vulnrichment, bool, error)
}

func EnrichFindings(ctx context.Context, findings []model.Finding, epssStore EPSSStore, vulnrichmentStore VulnrichmentStore) ([]model.Finding, error) {
	enriched := append([]model.Finding(nil), findings...)
	for i := range enriched {
		if epssStore != nil {
			epss, ok, err := epssStore.LookupContext(ctx, enriched[i].ID)
			if err != nil {
				return nil, err
			}
			if ok {
				value := epss
				enriched[i].EPSS = &value
			}
		}

		if vulnrichmentStore != nil {
			vulnrichment, ok, err := vulnrichmentStore.LookupContext(ctx, enriched[i].ID)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					continue
				}
				return nil, err
			}
			if ok {
				value := vulnrichment
				enriched[i].Vulnrichment = &value
			}
		}
	}
	return enriched, nil
}
