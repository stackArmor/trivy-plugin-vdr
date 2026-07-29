package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/stackArmor/trivy-plugin-vdr/internal/chainanalysis"
	"github.com/stackArmor/trivy-plugin-vdr/internal/chaincatalog"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
	"github.com/stackArmor/trivy-plugin-vdr/internal/report"
)

func runEnrichReport(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("vdr enrich-report", flag.ContinueOnError)
	flags.SetOutput(stdout)
	var inputPath string
	var outputPath string
	var htmlOutput string
	var htmlTemplate string
	flags.StringVar(&inputPath, "input", "", "VDR JSON report path, or - for stdin")
	flags.StringVar(&inputPath, "i", "", "alias for --input")
	flags.StringVar(&outputPath, "output", "", "enriched JSON output path; stdout when omitted")
	flags.StringVar(&outputPath, "o", "", "alias for --output")
	flags.StringVar(&htmlOutput, "html-output", "", "optional standalone HTML output path")
	flags.StringVar(&htmlTemplate, "html-template", "", "custom HTML template path")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Enrich an existing VDR JSON report with the embedded CAPEC/ATT&CK taxonomy catalog.")
		fmt.Fprintln(flags.Output(), "\nUsage:\n  vdr enrich-report --input REPORT.json [--output ENRICHED.json] [flags]")
		fmt.Fprintln(flags.Output(), "\nFlags:")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if inputPath == "" && flags.NArg() == 1 {
		inputPath = flags.Arg(0)
	} else if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q; use --input REPORT.json", flags.Arg(0))
	}
	if inputPath == "" {
		return errors.New("--input is required")
	}

	var input io.Reader
	var inputFile *os.File
	if inputPath == "-" {
		input = stdin
	} else {
		file, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("open input report: %w", err)
		}
		inputFile = file
		input = file
		defer inputFile.Close()
	}

	var value model.Report
	decoder := json.NewDecoder(input)
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("decode input report: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode input report: multiple JSON values")
		}
		return fmt.Errorf("decode input report trailing data: %w", err)
	}
	switch value.ReportSchemaVersion {
	case "", "1", "2", report.ReportSchemaVersion:
	default:
		return fmt.Errorf("unsupported VDR report schema %q", value.ReportSchemaVersion)
	}

	catalog, err := chaincatalog.Builtin()
	if err != nil {
		return err
	}
	enrichExistingReport(&value, catalog)

	if outputPath == "" || outputPath == "-" {
		if err := report.RenderJSON(stdout, value); err != nil {
			return fmt.Errorf("write enriched report: %w", err)
		}
	} else if err := writeJSONReportAtomic(outputPath, value); err != nil {
		return err
	}
	if htmlOutput != "" {
		if err := writeHTMLReportAtomic(htmlOutput, value, htmlTemplate); err != nil {
			return err
		}
	}
	return nil
}

func enrichExistingReport(value *model.Report, catalog *chaincatalog.Catalog) {
	value.ReportSchemaVersion = report.ReportSchemaVersion
	value.ChainCatalog = chainanalysis.CatalogMetadata(catalog)
	chainanalysis.AnnotateFindings(value.Findings, catalog)
	chainanalysis.AnnotateFindings(value.SuppressedFindings, catalog)
	for i := range value.Resources {
		chainanalysis.AnnotateFindings(value.Resources[i].Findings, catalog)
	}
	value.CAPECTransitions = chainanalysis.FindReportTransitions(value.Findings, value.Resources, catalog)

	coverage := value.Findings
	if len(coverage) == 0 && len(value.Resources) > 0 {
		coverage = uniqueResourceFindings(value.Resources)
		if value.Summary.Findings > 0 && len(coverage) != value.Summary.Findings {
			value.Warnings = appendUnique(value.Warnings,
				fmt.Sprintf("chain taxonomy coverage derived from %d unique resource-view findings; report summary records %d findings", len(coverage), value.Summary.Findings))
		}
	}
	value.Summary.ChainTaxonomy = chainanalysis.SummarizeTaxonomy(coverage)
	chainanalysis.AddTransitionSummary(value.Summary.ChainTaxonomy, value.CAPECTransitions)
}

type reportFindingKey struct {
	ID               string
	PackageName      string
	InstalledVersion string
}

func uniqueResourceFindings(resources []model.ResourceReport) []model.Finding {
	index := map[reportFindingKey]int{}
	var result []model.Finding
	for _, resource := range resources {
		for _, finding := range resource.Findings {
			key := reportFindingKey{
				ID:               finding.ID,
				PackageName:      finding.PackageName,
				InstalledVersion: finding.InstalledVersion,
			}
			at, ok := index[key]
			if !ok {
				index[key] = len(result)
				result = append(result, finding)
				continue
			}
			if taxonomyRank(finding.ChainTaxonomy) > taxonomyRank(result[at].ChainTaxonomy) {
				result[at] = finding
			}
		}
	}
	return result
}

func taxonomyRank(value *model.ChainTaxonomyEvidence) int {
	if value == nil {
		return 0
	}
	if value.Status == chainanalysis.StatusMapped {
		return 1000 + len(value.Paths)
	}
	return 1
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func writeJSONReportAtomic(path string, value model.Report) error {
	return writeAtomic(path, func(writer io.Writer) error {
		return report.RenderJSON(writer, value)
	})
}

func writeHTMLReportAtomic(path string, value model.Report, templatePath string) error {
	return writeAtomic(path, func(writer io.Writer) error {
		return report.RenderHTML(writer, value, templatePath)
	})
}

func writeAtomic(path string, render func(io.Writer) error) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".vdr-enrich-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tempPath := file.Name()
	keep := false
	defer func() {
		file.Close()
		if !keep {
			os.Remove(tempPath)
		}
	}()
	if err := render(file); err != nil {
		return fmt.Errorf("render %s: %w", path, err)
	}
	if err := file.Chmod(0o644); err != nil {
		return fmt.Errorf("set output permissions: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace output %s: %w", path, err)
	}
	keep = true
	return nil
}
