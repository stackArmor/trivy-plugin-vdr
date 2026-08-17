package enrich

import (
	"context"
	"errors"
	"fmt"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

var (
	ErrNotFound          = errors.New("enrichment not found")
	ErrSourceUnavailable = errors.New("enrichment source unavailable")
)

const maxVulnrichmentWarnings = 5

// Warning captures a non-fatal enrichment issue encountered during a run.
type Warning struct {
	Source  string // "EPSS" or "Vulnrichment"
	CVEID   string // CVE ID, or empty for store-level warnings
	Message string // Human-readable warning message
}

func (w Warning) String() string {
	if w.CVEID != "" {
		return fmt.Sprintf("%s (%s): %s", w.Source, w.CVEID, w.Message)
	}
	return fmt.Sprintf("%s: %s", w.Source, w.Message)
}

type EPSSStore interface {
	LookupContext(ctx context.Context, cveID string) (model.EPSS, bool, error)
}

type VulnrichmentStore interface {
	LookupContext(ctx context.Context, cveID string) (model.Vulnrichment, bool, error)
}

// EnrichFindings decorates findings with EPSS and Vulnrichment data.
//
// Enrichment is best-effort and non-fatal: network and parsing failures produce Warnings
// rather than aborting the scan. If context cancellation occurs, the partial findings,
// warnings collected so far, and the context error are returned.
func EnrichFindings(ctx context.Context, findings []model.Finding, epssStore EPSSStore, vulnrichmentStore VulnrichmentStore) ([]model.Finding, []Warning, error) {
	enriched := append([]model.Finding(nil), findings...)
	var warnings []Warning
	var vulnrichmentErrCount int
	var vulnrichmentSuppressed bool

	for i := range enriched {
		if err := ctx.Err(); err != nil {
			return enriched, warnings, err
		}

		if epssStore != nil {
			epss, ok, err := epssStore.LookupContext(ctx, enriched[i].ID)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return enriched, warnings, err
				}
				warnings = append(warnings, Warning{
					Source:  "EPSS",
					Message: fmt.Sprintf("failed to load dataset: %v (EPSS enrichment skipped for all findings)", err),
				})
				epssStore = nil // disable for remainder of run
			} else if ok {
				value := epss
				enriched[i].EPSS = &value
			}
		}

		if vulnrichmentStore != nil {
			vrich, ok, err := vulnrichmentStore.LookupContext(ctx, enriched[i].ID)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return enriched, warnings, err
				}
				if errors.Is(err, ErrNotFound) {
					// missing record is normal
				} else if errors.Is(err, ErrSourceUnavailable) {
					if !vulnrichmentSuppressed {
						vulnrichmentSuppressed = true
						warnings = append(warnings, Warning{
							Source:  "Vulnrichment",
							Message: "source unavailable (circuit breaker tripped; skipped for remaining findings)",
						})
					}
				} else {
					vulnrichmentErrCount++
					if vulnrichmentErrCount <= maxVulnrichmentWarnings {
						warnings = append(warnings, Warning{
							Source:  "Vulnrichment",
							CVEID:   enriched[i].ID,
							Message: err.Error(),
						})
					}
				}
			} else if ok {
				value := vrich
				enriched[i].Vulnrichment = &value
				enriched[i].CWEs = append([]string(nil), value.CWEs...)
			}
		}
	}

	if vulnrichmentErrCount > maxVulnrichmentWarnings {
		warnings = append(warnings, Warning{
			Source:  "Vulnrichment",
			Message: fmt.Sprintf("%d additional CVE lookup failures suppressed", vulnrichmentErrCount-maxVulnrichmentWarnings),
		})
	}

	return enriched, warnings, nil
}
