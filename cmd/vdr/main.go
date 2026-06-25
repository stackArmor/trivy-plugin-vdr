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
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/report"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scanner"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
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
	switch cfg.Source {
	case config.SourceK8s:
		return runK8s(context.Background(), cfg, os.Stdout)
	default:
		return fmt.Errorf("source %q is not implemented yet", cfg.Source)
	}
}

func runK8s(ctx context.Context, cfg config.Config, stdout io.Writer) error {
	collector, _, err := k8s.NewForCurrentContext()
	if err != nil {
		return err
	}

	k8sOptions := k8s.Options{
		Namespaces:            cfg.Namespaces,
		AllNamespaces:         cfg.AllNamespaces,
		IncludeZeroDaemonSets: cfg.IncludeZeroDaemonSets,
	}
	inventory, err := collector.Collect(ctx, k8sOptions)
	if err != nil {
		return err
	}

	trivyRunner := scanner.TrivyRunner{ImageSrc: cfg.ImageSrc, CacheDir: cfg.CacheDir}
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

	if !cfg.SkipEnrichment {
		epssStore := epss.NewStore(cfg.CacheDir, epss.WithForceRefresh(cfg.RefreshEnrichment))
		vulnrichmentStore := vulnrichment.NewStore(cfg.CacheDir, vulnrichment.WithForceRefresh(cfg.RefreshEnrichment))
		findings, err = enrich.EnrichFindings(ctx, findings, epssStore, vulnrichmentStore)
		if err != nil {
			return err
		}
	}

	warnings := scannerWarnings(scanWarnings)
	exposures := map[model.ResourceRef]model.Exposure{}
	if !cfg.SkipExposure {
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
	}
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
		if warning.ImageRef == "" {
			messages = append(messages, warning.Message)
			continue
		}
		messages = append(messages, fmt.Sprintf("%s: %s", warning.ImageRef, warning.Message))
	}
	return messages
}
