package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/stackArmor/trivy-plugin-vdr/internal/config"
	"github.com/stackArmor/trivy-plugin-vdr/internal/enrich"
	"github.com/stackArmor/trivy-plugin-vdr/internal/enrich/epss"
	"github.com/stackArmor/trivy-plugin-vdr/internal/enrich/vulnrichment"
	"github.com/stackArmor/trivy-plugin-vdr/internal/exposure"
	"github.com/stackArmor/trivy-plugin-vdr/internal/k8s"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/registry"
	"github.com/stackArmor/trivy-plugin-vdr/internal/report"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scanner"
)

// errCompletedWithFailures signals that the run finished and wrote its report,
// but some images failed to scan. main() maps it to a non-zero exit code
// without printing a fatal-error message (the failures were already logged).
var errCompletedWithFailures = errors.New("completed with scan failures")

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if errors.Is(err, errCompletedWithFailures) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "vdr: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	cfg, err := config.ParseWithOutput(args, os.Stdout)
	if err != nil {
		return err
	}
	logger := log.New(log.LevelFromFlags(cfg.Quiet, cfg.Debug))
	switch cfg.Source {
	case config.SourceK8s:
		return runK8s(context.Background(), cfg, logger, os.Stdout)
	default:
		return fmt.Errorf("source %q is not implemented yet", cfg.Source)
	}
}

func runK8s(ctx context.Context, cfg config.Config, logger *log.Logger, stdout io.Writer) error {
	collector, contextName, err := k8s.NewForCurrentContext()
	if err != nil {
		return err
	}

	k8sOptions := k8s.Options{
		Namespaces:            cfg.Namespaces,
		AllNamespaces:         cfg.AllNamespaces,
		IncludeZeroDaemonSets: cfg.IncludeZeroDaemonSets,
	}
	logger.Info("collecting Kubernetes inventory from context %q", contextName)
	inventory, err := collector.Collect(ctx, k8sOptions)
	if err != nil {
		return err
	}
	logger.Info("inventory: %d workloads, %d unique images", len(inventory.Resources), len(inventory.Images))

	var warnings []string

	var dockerConfigDir string
	if !cfg.SkipRegistryAuth {
		secretAuths, secretWarnings, err := collector.CollectPullSecretAuths(ctx, k8sOptions, logger)
		if err != nil {
			return err
		}
		warnings = append(warnings, secretWarnings...)

		res, err := registry.Build(ctx, inventoryImageRefs(inventory), secretAuths, registry.Options{
			EnableGcloud: !cfg.NoGcloudAuth,
			EnableECR:    !cfg.NoECRAuth,
		}, logger)
		if err != nil {
			return err
		}
		defer res.Cleanup()
		dockerConfigDir = res.Dir
		for _, w := range res.Warnings {
			warnings = append(warnings, "registry auth: "+w)
		}
		logger.Info("registry auth: configured credentials for %d registries (%d from cluster secrets)", res.Registries, len(secretAuths))
		for _, w := range secretWarnings {
			logger.Warn("%s", w)
		}
		for _, w := range res.Warnings {
			logger.Warn("registry auth: %s", w)
		}
	}

	trivyRunner := scanner.TrivyRunner{ImageSrc: cfg.ImageSrc, CacheDir: cfg.CacheDir, DockerConfigDir: dockerConfigDir}
	logger.Info("scanning %d images with Trivy (%d parallel)", len(inventory.Images), cfg.ParallelScans)
	findings, scanWarnings, err := scanner.ScanInventoryWithOptions(ctx, inventory, trivyRunner, scanner.ScanOptions{
		Timeout:             cfg.Timeout,
		ParallelScans:       cfg.ParallelScans,
		CacheCleanup:        scanner.CleanupPolicy(cfg.CacheCleanup),
		CacheDir:            cfg.CacheDir,
		CacheMinFreeGB:      cfg.CacheMinFreeGB,
		CacheMinFreePercent: cfg.CacheMinFreePercent,
	})
	if err != nil {
		return err
	}
	scanFailures := imageFailureCount(scanWarnings)
	logger.Info("scan complete: %d findings, %d images failed", len(findings), scanFailures)
	for _, w := range scanWarnings {
		logger.Warn("%s", warningText(w))
	}

	if !cfg.SkipEnrichment {
		logger.Info("enriching findings with EPSS and vulnrichment data")
		epssStore := epss.NewStore(cfg.CacheDir, epss.WithForceRefresh(cfg.RefreshEnrichment), epss.WithLogger(logger))
		vulnrichmentStore := vulnrichment.NewStore(cfg.CacheDir, vulnrichment.WithForceRefresh(cfg.RefreshEnrichment))
		findings, err = enrich.EnrichFindings(ctx, findings, epssStore, vulnrichmentStore)
		if err != nil {
			return err
		}
		fetched, cached := vulnrichmentStore.Stats()
		logger.Info("vulnrichment: %d records fetched, %d from cache", fetched, cached)
	}

	warnings = append(warnings, scannerWarnings(scanWarnings)...)
	exposures := map[model.ResourceRef]model.Exposure{}
	if !cfg.SkipExposure {
		logger.Info("analyzing service exposure")
		objects, exposureWarnings, err := collector.CollectExposureObjectsWithWarnings(ctx, k8sOptions)
		if err != nil {
			return err
		}
		warnings = append(warnings, exposureWarnings...)
		exposures = exposure.Analyze(inventory, objects)
	}

	primary := report.Build(inventory, findings, exposures, report.Options{
		View:        cfg.View,
		MinSeverity: cfg.MinSeverity,
		MinEPSS:     cfg.MinEPSS,
		Warnings:    warnings,
	})
	if err := writePrimaryReport(stdout, cfg.Output, cfg.Format, primary); err != nil {
		return err
	}
	if cfg.HTMLOutput != "" {
		htmlReport := report.Build(inventory, findings, exposures, report.Options{
			View:        report.ViewResources,
			MinSeverity: cfg.MinSeverity,
			MinEPSS:     cfg.MinEPSS,
			Warnings:    warnings,
		})
		if err := writeHTMLReport(cfg.HTMLOutput, cfg.HTMLTemplate, htmlReport); err != nil {
			return err
		}
		logger.Info("wrote HTML report to %s", cfg.HTMLOutput)
	}

	if scanFailures > 0 {
		logger.Error("completed with %d image scan failure(s); see warnings in the report", scanFailures)
		return errCompletedWithFailures
	}
	logger.Info("completed successfully")
	return nil
}

func writePrimaryReport(stdout io.Writer, path, format string, scanReport model.Report) error {
	writer := stdout
	var file *os.File
	if path != "" {
		var err error
		file, err = os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()
		writer = file
	}
	switch format {
	case config.FormatJSON:
		return report.RenderJSON(writer, scanReport)
	case config.FormatTable:
		return report.RenderTable(writer, scanReport)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func writeHTMLReport(path, templatePath string, scanReport model.Report) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return report.RenderHTML(file, scanReport, templatePath)
}

func scannerWarnings(warnings []scanner.Warning) []string {
	messages := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		messages = append(messages, warningText(warning))
	}
	return messages
}

func warningText(warning scanner.Warning) string {
	if warning.ImageRef == "" {
		return warning.Message
	}
	return fmt.Sprintf("%s: %s", warning.ImageRef, warning.Message)
}

// imageFailureCount returns the number of warnings that represent a failed image
// scan (those carrying an image reference).
func imageFailureCount(warnings []scanner.Warning) int {
	n := 0
	for _, warning := range warnings {
		if warning.ImageRef != "" {
			n++
		}
	}
	return n
}

// inventoryImageRefs returns the de-duplicated image references in the inventory.
func inventoryImageRefs(inventory *model.Inventory) []string {
	if inventory == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(inventory.Images))
	refs := make([]string, 0, len(inventory.Images))
	for _, image := range inventory.Images {
		if image.ImageRef == "" {
			continue
		}
		if _, ok := seen[image.ImageRef]; ok {
			continue
		}
		seen[image.ImageRef] = struct{}{}
		refs = append(refs, image.ImageRef)
	}
	return refs
}
