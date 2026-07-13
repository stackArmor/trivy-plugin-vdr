package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/stackArmor/trivy-plugin-vdr/internal/cloudrun"
	"github.com/stackArmor/trivy-plugin-vdr/internal/config"
	"github.com/stackArmor/trivy-plugin-vdr/internal/ecs"
	"github.com/stackArmor/trivy-plugin-vdr/internal/enrich"
	"github.com/stackArmor/trivy-plugin-vdr/internal/enrich/epss"
	"github.com/stackArmor/trivy-plugin-vdr/internal/enrich/vulnrichment"
	"github.com/stackArmor/trivy-plugin-vdr/internal/exposure"
	helmsource "github.com/stackArmor/trivy-plugin-vdr/internal/helm"
	imageinventory "github.com/stackArmor/trivy-plugin-vdr/internal/image"
	"github.com/stackArmor/trivy-plugin-vdr/internal/k8s"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
	"github.com/stackArmor/trivy-plugin-vdr/internal/manifest"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/registry"
	"github.com/stackArmor/trivy-plugin-vdr/internal/report"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scanner"
	"github.com/stackArmor/trivy-plugin-vdr/internal/scoring"
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
	case config.SourceCloudRun:
		return runCloudRun(context.Background(), cfg, logger, os.Stdout)
	case config.SourceECS:
		return runECS(context.Background(), cfg, logger, os.Stdout)
	case config.SourceImage:
		return runImage(context.Background(), cfg, logger, os.Stdout)
	case config.SourceHelm:
		return runHelm(context.Background(), cfg, logger, os.Stdout)
	default:
		return fmt.Errorf("source %q is not implemented yet", cfg.Source)
	}
}

func runHelm(ctx context.Context, cfg config.Config, logger *log.Logger, stdout io.Writer) error {
	namespace := cfg.Namespaces[0]
	applicationChart := helmsource.Chart{
		Reference:   cfg.Chart,
		Version:     cfg.ChartVersion,
		Repository:  cfg.ChartRepo,
		ReleaseName: cfg.ReleaseName,
		Namespace:   namespace,
		ValuesFiles: cfg.ValuesFiles,
		KubeVersion: cfg.KubeVersion,
		APIVersions: cfg.APIVersions,
		IncludeCRDs: cfg.IncludeCRDs,
	}
	logger.Info("rendering Helm chart %q as release %q in namespace %q", cfg.Chart, cfg.ReleaseName, namespace)
	applicationYAML, err := helmsource.Render(ctx, applicationChart)
	if err != nil {
		return err
	}
	documents := []manifest.Document{{Name: cfg.Chart, YAML: applicationYAML, DefaultNamespace: namespace}}

	if cfg.IngressChart != "" {
		ingressChart := helmsource.Chart{
			Reference:   cfg.IngressChart,
			Version:     cfg.IngressChartVersion,
			Repository:  cfg.IngressChartRepo,
			ReleaseName: cfg.IngressReleaseName,
			Namespace:   cfg.IngressNamespace,
			ValuesFiles: cfg.IngressValuesFiles,
			KubeVersion: cfg.KubeVersion,
			APIVersions: cfg.APIVersions,
			IncludeCRDs: cfg.IncludeCRDs,
		}
		logger.Info("rendering ingress/Gateway Helm chart %q as release %q in namespace %q", cfg.IngressChart, cfg.IngressReleaseName, cfg.IngressNamespace)
		ingressYAML, renderErr := helmsource.Render(ctx, ingressChart)
		if renderErr != nil {
			return renderErr
		}
		documents = append(documents, manifest.Document{Name: cfg.IngressChart, YAML: ingressYAML, DefaultNamespace: cfg.IngressNamespace})
	}

	var clusterDefaults map[string]string
	if cfg.ConfigMap != "" {
		clusterDefaults, err = manifest.LoadConfigMap(cfg.ConfigMap)
		if err != nil {
			return err
		}
		logger.Info("loaded Helm scan ConfigMap from %s", cfg.ConfigMap)
	}

	collection, err := manifest.Collect(ctx, documents, manifest.Options{
		ContextName:        "helm:" + cfg.Chart,
		ClusterDefaults:    clusterDefaults,
		CollectPullSecrets: !cfg.SkipRegistryAuth,
	}, logger)
	if err != nil {
		return err
	}
	inventory := collection.Inventory
	logger.Info("inventory: %d rendered workloads, %d unique images", len(inventory.Resources), len(inventory.Images))
	warnings := append([]string(nil), collection.Warnings...)
	for _, warning := range warnings {
		logger.Warn("%s", warning)
	}

	exposures := map[model.ResourceRef]model.Exposure{}
	if !cfg.SkipExposure {
		logger.Info("analyzing declared Ingress and Gateway exposure from rendered manifests")
		exposures = exposure.AnalyzeWithOptions(inventory, collection.ExposureObjects, exposure.AnalyzeOptions{Declared: true})
		warning := "Helm exposure is evaluated from rendered deployment intent; load-balancer provisioning and runtime status were not observed"
		warnings = append(warnings, warning)
		logger.Warn("%s", warning)
	}
	if cfg.ReachabilityOnly {
		logger.Info("reachability-only mode: skipping registry authentication and Trivy image scans")
		return reportInventory(cfg, logger, stdout, inventory, nil, warnings, exposures)
	}

	var dockerConfigDir string
	var registryAuths map[string]registry.DockerAuth
	if !cfg.SkipRegistryAuth {
		res, buildErr := registry.Build(ctx, inventoryImageRefs(inventory), collection.PullSecretAuths, registry.Options{
			EnableGcloud:                 !cfg.NoGcloudAuth,
			EnableECR:                    !cfg.NoECRAuth,
			GCPImpersonateServiceAccount: cfg.GCPImpersonateServiceAccount,
			AWSRoleARN:                   cfg.AWSRoleARN,
		}, logger)
		if buildErr != nil {
			return buildErr
		}
		defer res.Cleanup()
		dockerConfigDir = res.Dir
		registryAuths = res.Credentials
		for _, warning := range res.Warnings {
			warnings = append(warnings, "registry auth: "+warning)
			logger.Warn("registry auth: %s", warning)
		}
		logger.Info("registry auth: configured credentials for %d registries (%d from rendered secrets)", res.Registries, len(collection.PullSecretAuths))
	}

	return scanAndReport(ctx, cfg, logger, stdout, inventory, warnings, dockerConfigDir, registryAuths, exposures)
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
	for _, w := range inventory.Warnings {
		logger.Warn("%s", w)
	}
	warnings = append(warnings, inventory.Warnings...)

	exposures := map[model.ResourceRef]model.Exposure{}
	if !cfg.SkipExposure {
		logger.Info("analyzing service exposure")
		objects, exposureWarnings, err := collector.CollectExposureObjectsWithWarnings(ctx, k8sOptions)
		if err != nil {
			return err
		}
		warnings = append(warnings, exposureWarnings...)
		objects.InternetAccessibleIngressClasses, objects.InternetAccessibleGatewayClasses =
			exposure.ClassOverridesFromConfigMap(inventory.ClusterDefaults)
		exposures = exposure.Analyze(inventory, objects)
	}
	if cfg.ReachabilityOnly {
		logger.Info("reachability-only mode: skipping registry authentication and Trivy image scans")
		return reportInventory(cfg, logger, stdout, inventory, nil, warnings, exposures)
	}

	var dockerConfigDir string
	var registryAuths map[string]registry.DockerAuth
	if !cfg.SkipRegistryAuth {
		secretAuths, secretWarnings, err := collector.CollectPullSecretAuths(ctx, k8sOptions, logger)
		if err != nil {
			return err
		}
		warnings = append(warnings, secretWarnings...)

		res, err := registry.Build(ctx, inventoryImageRefs(inventory), secretAuths, registry.Options{
			EnableGcloud:                 !cfg.NoGcloudAuth,
			EnableECR:                    !cfg.NoECRAuth,
			GCPImpersonateServiceAccount: cfg.GCPImpersonateServiceAccount,
			AWSRoleARN:                   cfg.AWSRoleARN,
		}, logger)
		if err != nil {
			return err
		}
		defer res.Cleanup()
		dockerConfigDir = res.Dir
		registryAuths = res.Credentials
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

	return scanAndReport(ctx, cfg, logger, stdout, inventory, warnings, dockerConfigDir, registryAuths, exposures)
}

func runCloudRun(ctx context.Context, cfg config.Config, logger *log.Logger, stdout io.Writer) error {
	client, err := cloudrun.NewGCPClient(ctx, cloudrun.ClientOptions{ImpersonateServiceAccount: cfg.GCPImpersonateServiceAccount})
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			logger.Warn("closing Google Cloud clients: %v", closeErr)
		}
	}()

	options := cloudrun.Options{Project: cfg.Project, Regions: cfg.Regions}
	collector := cloudrun.Collector{Client: client}
	logger.Info("collecting Cloud Run inventory from project %q regions %v", cfg.Project, cfg.Regions)
	inventory, services, jobs, err := collector.CollectResources(ctx, options)
	if err != nil {
		return err
	}
	logger.Info("inventory: %d Cloud Run resources, %d unique images", len(inventory.Resources), len(inventory.Images))

	var warnings []string
	for _, w := range inventory.Warnings {
		logger.Warn("%s", w)
	}
	warnings = append(warnings, inventory.Warnings...)

	exposures := map[model.ResourceRef]model.Exposure{}
	if !cfg.SkipExposure {
		logger.Info("analyzing Cloud Run exposure")
		cloudRunExposures, exposureWarnings, err := cloudrun.AnalyzeExposure(ctx, inventory, services, jobs, client)
		if err != nil {
			return err
		}
		exposures = cloudRunExposures
		for _, w := range exposureWarnings {
			warnings = append(warnings, w)
			logger.Warn("%s", w)
		}
	}
	if cfg.ReachabilityOnly {
		logger.Info("reachability-only mode: skipping registry authentication and Trivy image scans")
		return reportInventory(cfg, logger, stdout, inventory, nil, warnings, exposures)
	}

	var dockerConfigDir string
	var registryAuths map[string]registry.DockerAuth
	if !cfg.SkipRegistryAuth {
		res, err := registry.Build(ctx, inventoryImageRefs(inventory), nil, registry.Options{
			EnableGcloud:                 !cfg.NoGcloudAuth,
			EnableECR:                    !cfg.NoECRAuth,
			GCPImpersonateServiceAccount: cfg.GCPImpersonateServiceAccount,
			AWSRoleARN:                   cfg.AWSRoleARN,
		}, logger)
		if err != nil {
			return err
		}
		defer res.Cleanup()
		dockerConfigDir = res.Dir
		registryAuths = res.Credentials
		for _, w := range res.Warnings {
			warnings = append(warnings, "registry auth: "+w)
			logger.Warn("registry auth: %s", w)
		}
		logger.Info("registry auth: configured credentials for %d registries", res.Registries)
	}

	return scanAndReport(ctx, cfg, logger, stdout, inventory, warnings, dockerConfigDir, registryAuths, exposures)
}

func runECS(ctx context.Context, cfg config.Config, logger *log.Logger, stdout io.Writer) error {
	client, err := ecs.NewAWSClient(ctx, ecs.ClientOptions{})
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			logger.Warn("closing AWS clients: %v", closeErr)
		}
	}()

	options := ecs.Options{Regions: cfg.Regions}
	collector := ecs.Collector{Client: client}
	logger.Info("collecting ECS inventory from regions %v", cfg.Regions)
	inventory, taskDefinitions, err := collector.CollectResources(ctx, options)
	if err != nil {
		return err
	}
	var warnings []string
	for _, w := range inventory.Warnings {
		logger.Warn("%s", w)
	}
	warnings = append(warnings, inventory.Warnings...)

	runtimeSignals, runtimeWarnings := client.CollectRuntimeSignals(ctx, cfg.Regions)
	for _, w := range runtimeWarnings {
		warnings = append(warnings, w)
		logger.Warn("%s", w)
	}
	runtimeMetadata := ecs.AnalyzeRuntime(taskDefinitions, runtimeSignals)
	ecs.AttachRuntimeMetadata(inventory, runtimeMetadata)
	logger.Info("inventory: %d ECS resources, %d unique images", len(inventory.Resources), len(inventory.Images))

	exposures := map[model.ResourceRef]model.Exposure{}
	if !cfg.SkipExposure {
		exposureGraph, exposureWarnings := client.CollectExposureGraph(ctx, cfg.Regions, taskDefinitions)
		for _, w := range exposureWarnings {
			warnings = append(warnings, w)
			logger.Warn("%s", w)
		}
		exposures = ecs.AnalyzeExposureFromGraph(inventory, runtimeMetadata, exposureGraph)
	}
	if cfg.ReachabilityOnly {
		logger.Info("reachability-only mode: skipping registry authentication and Trivy image scans")
		return reportInventory(cfg, logger, stdout, inventory, nil, warnings, exposures)
	}

	var dockerConfigDir string
	var registryAuths map[string]registry.DockerAuth
	if !cfg.SkipRegistryAuth {
		secretAuths, secretWarnings := ecs.RepositoryCredentialAuths(ctx, taskDefinitions, client)
		for _, w := range secretWarnings {
			warnings = append(warnings, "registry auth: "+w)
			logger.Warn("registry auth: %s", w)
		}
		res, err := registry.Build(ctx, inventoryImageRefs(inventory), secretAuths, registry.Options{
			EnableGcloud:                 !cfg.NoGcloudAuth,
			EnableECR:                    !cfg.NoECRAuth,
			GCPImpersonateServiceAccount: cfg.GCPImpersonateServiceAccount,
			AWSRoleARN:                   cfg.AWSRoleARN,
		}, logger)
		if err != nil {
			return err
		}
		defer res.Cleanup()
		dockerConfigDir = res.Dir
		registryAuths = res.Credentials
		for _, w := range res.Warnings {
			warnings = append(warnings, "registry auth: "+w)
			logger.Warn("registry auth: %s", w)
		}
		logger.Info("registry auth: configured credentials for %d registries", res.Registries)
	}

	return scanAndReport(ctx, cfg, logger, stdout, inventory, warnings, dockerConfigDir, registryAuths, exposures)
}

func runImage(ctx context.Context, cfg config.Config, logger *log.Logger, stdout io.Writer) error {
	inventory := imageinventory.Collect(cfg.ImageRefs)
	logger.Info("inventory: %d standalone images", len(inventory.Images))

	var warnings []string
	var dockerConfigDir string
	var registryAuths map[string]registry.DockerAuth
	if !cfg.SkipRegistryAuth {
		res, err := registry.Build(ctx, inventoryImageRefs(inventory), nil, registry.Options{
			EnableGcloud:                 !cfg.NoGcloudAuth,
			EnableECR:                    !cfg.NoECRAuth,
			GCPImpersonateServiceAccount: cfg.GCPImpersonateServiceAccount,
			AWSRoleARN:                   cfg.AWSRoleARN,
		}, logger)
		if err != nil {
			return err
		}
		defer res.Cleanup()
		dockerConfigDir = res.Dir
		registryAuths = res.Credentials
		for _, w := range res.Warnings {
			warnings = append(warnings, "registry auth: "+w)
			logger.Warn("registry auth: %s", w)
		}
		logger.Info("registry auth: configured credentials for %d registries", res.Registries)
	}

	return scanAndReport(ctx, cfg, logger, stdout, inventory, warnings, dockerConfigDir, registryAuths, nil)
}

func scanAndReport(ctx context.Context, cfg config.Config, logger *log.Logger, stdout io.Writer, inventory *model.Inventory, warnings []string, dockerConfigDir string, registryAuths map[string]registry.DockerAuth, exposures map[model.ResourceRef]model.Exposure) error {
	trivyRunner := scanner.TrivyRunner{
		ImageSrc:         cfg.ImageSrc,
		CacheDir:         cfg.CacheDir,
		DockerConfigDir:  dockerConfigDir,
		RegistryAuths:    registryAuths,
		OCIVEXIncluded:   cfg.OCIVEXIncluded,
		VEXOCIRegistries: cfg.VEXOCIRegistries,
		Logger:           logger,
	}
	logger.Info("downloading Trivy vulnerability and Java databases")
	if dbErr := trivyRunner.EnsureDatabases(ctx); dbErr != nil {
		logger.Error("database download failed: %v", dbErr)
		warnings = append(warnings, fmt.Sprintf("database download failed: %v", dbErr))
	} else {
		logger.Info("databases ready")
		trivyRunner.SkipDBUpdate = true
	}
	trivyRunner = trivyRunner.WithSelfHeal()

	// For parallel scans, give each worker an isolated cache directory (databases
	// hardlinked from the shared cache, private scan cache) so concurrent scans
	// don't deadlock on Trivy's shared cache lock.
	if cfg.ParallelScans > 1 {
		runnerWithCaches, cleanup, cacheErr := trivyRunner.PrepareWorkerCaches(cfg.ParallelScans)
		if cacheErr != nil {
			logger.Warn("could not prepare isolated scan caches (%v); scanning may be unreliable in parallel", cacheErr)
		} else {
			trivyRunner = runnerWithCaches
			defer cleanup()
			logger.Info("prepared %d isolated scan caches", cfg.ParallelScans)
		}
	}

	logger.Info("scanning %d images with Trivy (%d parallel)", len(inventory.Images), cfg.ParallelScans)
	findings, scanWarnings, err := scanner.ScanInventoryWithOptions(ctx, inventory, trivyRunner, scanner.ScanOptions{
		Timeout:             cfg.Timeout,
		ParallelScans:       cfg.ParallelScans,
		CacheCleanup:        scanner.CleanupPolicy(cfg.CacheCleanup),
		CacheDir:            cfg.CacheDir,
		CacheMinFreeGB:      cfg.CacheMinFreeGB,
		CacheMinFreePercent: cfg.CacheMinFreePercent,
		Logger:              logger,
	})
	if err != nil {
		return err
	}
	// Per-image failures are already logged inline as they occur (with full
	// detail) by the scanner; here we only emit a concise aggregated summary.
	scanFailures := imageFailureCount(scanWarnings)
	if scanFailures > 0 {
		logger.Warn("%d of %d images failed to scan:", scanFailures, len(inventory.Images))
		for _, w := range scanWarnings {
			if w.ImageRef != "" {
				logger.Warn("  - %s", w.ImageRef)
			}
		}
	}
	logger.Info("scan complete: %d findings, %d images failed", len(findings), scanFailures)

	if !cfg.SkipEnrichment && !cfg.ScanReachabilityOnly {
		logger.Info("enriching findings with EPSS and vulnrichment data")
		epssStore := epss.NewStore(cfg.CacheDir, epss.WithForceRefresh(cfg.RefreshEnrichment), epss.WithLogger(logger))
		vulnrichmentStore := vulnrichment.NewStore(cfg.CacheDir, vulnrichment.WithForceRefresh(cfg.RefreshEnrichment))
		findings, err = enrich.EnrichFindings(ctx, findings, epssStore, vulnrichmentStore)
		if err != nil {
			return err
		}
		fetched, cached := vulnrichmentStore.Stats()
		logger.Info("vulnrichment: %d records fetched, %d from cache", fetched, cached)
	} else if cfg.ScanReachabilityOnly {
		logger.Info("scan-reachability-only mode: skipping EPSS and vulnrichment enrichment")
	}

	warnings = append(warnings, scannerWarnings(scanWarnings)...)

	if err := reportInventory(cfg, logger, stdout, inventory, findings, warnings, exposures); err != nil {
		return err
	}

	if scanFailures > 0 {
		logger.Error("completed with %d image scan failure(s); see warnings in the report", scanFailures)
		return errCompletedWithFailures
	}
	logger.Info("completed successfully")
	return nil
}

func reportInventory(cfg config.Config, logger *log.Logger, stdout io.Writer, inventory *model.Inventory, findings []model.Finding, warnings []string, exposures map[model.ResourceRef]model.Exposure) error {
	scoringConfig := scoring.Default()
	if cfg.ScoringConfig != "" {
		loaded, scErr := scoring.Load(cfg.ScoringConfig)
		if scErr != nil {
			return fmt.Errorf("load scoring config: %w", scErr)
		}
		scoringConfig = loaded
		logger.Info("loaded PAIN scoring config from %s", cfg.ScoringConfig)
	}
	// Cluster-wide FedRAMP defaults (class, multi-agency) from the in-cluster
	// ConfigMap override the config-file defaults.
	if inventory != nil && len(inventory.ClusterDefaults) > 0 {
		if applyErr := scoringConfig.ApplyClusterDefaults(inventory.ClusterDefaults); applyErr != nil {
			logger.Warn("ignoring invalid cluster FedRAMP config from ConfigMap: %v", applyErr)
		} else {
			logger.Info("applied cluster FedRAMP defaults (class=%s, default archetype=%s)", scoringConfig.Defaults.Class, scoringConfig.Defaults.Archetype)
		}
	}

	// The CycloneDX VEX output is asset-centric: it emits one vulnerability per
	// (CVE, affected asset) and attaches each asset's WorkloadPosture. The
	// resources view is what carries per-asset findings and posture, so build the
	// primary report with that view when CycloneDX is requested. The json and
	// table paths are unaffected and continue to honor cfg.View.
	primaryView := cfg.View
	if cfg.Format == config.FormatCycloneDX {
		primaryView = report.ViewResources
	}
	primary := report.Build(inventory, findings, exposures, report.Options{
		View:                primaryView,
		MinSeverity:         cfg.MinSeverity,
		MinEPSS:             cfg.MinEPSS,
		Warnings:            warnings,
		Scoring:             scoringConfig,
		ClassificationOnly:  cfg.ScanReachabilityOnly,
		SuppressEnrichments: cfg.ScanReachabilityOnly,
	})
	if err := writePrimaryReport(stdout, cfg.Output, cfg.Format, primary); err != nil {
		return err
	}
	if cfg.HTMLOutput != "" {
		htmlReport := report.Build(inventory, findings, exposures, report.Options{
			View:                report.ViewResources,
			MinSeverity:         cfg.MinSeverity,
			MinEPSS:             cfg.MinEPSS,
			Warnings:            warnings,
			Scoring:             scoringConfig,
			ClassificationOnly:  cfg.ScanReachabilityOnly,
			SuppressEnrichments: cfg.ScanReachabilityOnly,
		})
		if err := writeHTMLReport(cfg.HTMLOutput, cfg.HTMLTemplate, htmlReport); err != nil {
			return err
		}
		logger.Info("wrote HTML report to %s", cfg.HTMLOutput)
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
	case config.FormatCycloneDX:
		return report.RenderCycloneDX(writer, scanReport)
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
