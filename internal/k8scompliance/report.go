package k8scompliance

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

type ReportOptions struct {
	ScannerVersion string
	PluginVersion  string
	ClusterName    string
	Warnings       []string
	GeneratedAt    time.Time
}

func BuildReport(resources []ResourceReport, options ReportOptions) Report {
	generatedAt := options.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	report := Report{
		ReportSchemaVersion: ReportSchemaVersion,
		GeneratedAt:         generatedAt,
		ScannerVersion:      options.ScannerVersion,
		PluginVersion:       options.PluginVersion,
		ClusterName:         options.ClusterName,
		Resources:           resources,
		Warnings:            options.Warnings,
		Summary: Summary{
			Resources:  len(resources),
			BySeverity: map[string]int{},
		},
	}
	for _, resource := range resources {
		failed := false
		for _, result := range resource.Results {
			for _, check := range result.Checks {
				if !isFailure(check.Status) {
					continue
				}
				failed = true
				report.Summary.FailedChecks++
				severity := check.Severity
				if severity == "" {
					severity = "UNKNOWN"
				}
				report.Summary.BySeverity[severity]++
			}
		}
		if resource.Error != "" || failed {
			report.Summary.FailedResources++
		}
	}
	return report
}

func RenderJSON(writer io.Writer, report Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func RenderTable(writer io.Writer, report Report) error {
	renderedResources := 0
	for _, resource := range report.Resources {
		if !hasVisibleResult(resource) {
			continue
		}
		if renderedResources > 0 {
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
		}
		renderedResources++
		if _, err := fmt.Fprintln(writer, resourceHeading(resource)); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, strings.Repeat("=", len(resourceHeading(resource)))); err != nil {
			return err
		}
		successes, failures := resourceTestCounts(resource)
		if _, err := fmt.Fprintf(writer, "Tests: %d (SUCCESSES: %d, FAILURES: %d)\n\n", successes+failures, successes, failures); err != nil {
			return err
		}
		if resource.Error != "" {
			if _, err := fmt.Fprintf(writer, "ERROR: %s\n", resource.Error); err != nil {
				return err
			}
			continue
		}

		table := tabwriter.NewWriter(writer, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(table, "ID\tSEVERITY\tSTATUS\tTITLE\tMESSAGE"); err != nil {
			return err
		}
		for _, result := range resource.Results {
			for _, check := range result.Checks {
				if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
					check.ID,
					defaultString(check.Severity, "UNKNOWN"),
					defaultString(check.Status, "FAIL"),
					singleLine(check.Title),
					singleLine(check.Message),
				); err != nil {
					return err
				}
			}
		}
		if err := table.Flush(); err != nil {
			return err
		}
	}
	if renderedResources == 0 {
		if _, err := fmt.Fprintln(writer, "No Kubernetes compliance findings found."); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer,
		"\nSummary: %d resources, %d failed resources, %d failed checks (%s)\n",
		report.Summary.Resources,
		report.Summary.FailedResources,
		report.Summary.FailedChecks,
		formatSeveritySummary(report.Summary.BySeverity),
	); err != nil {
		return err
	}
	for _, warning := range report.Warnings {
		if _, err := fmt.Fprintf(writer, "WARNING: %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func resourceHeading(resource ResourceReport) string {
	scope := resource.Resource.Namespace
	if scope == "" {
		scope = "cluster"
	}
	heading := fmt.Sprintf("namespace: %s, %s: %s", scope, strings.ToLower(resource.Resource.Kind), resource.Resource.Name)
	if resource.ParentController != nil {
		heading += fmt.Sprintf(" (parent: %s/%s)", resource.ParentController.Kind, resource.ParentController.Name)
	}
	return heading
}

func resourceTestCounts(resource ResourceReport) (int, int) {
	var successes, failures int
	for _, result := range resource.Results {
		if result.MisconfSummary != nil {
			successes += result.MisconfSummary.Successes
			failures += result.MisconfSummary.Failures
			continue
		}
		for _, check := range result.Checks {
			if isFailure(check.Status) {
				failures++
			} else {
				successes++
			}
		}
	}
	return successes, failures
}

func hasVisibleResult(resource ResourceReport) bool {
	if resource.Error != "" {
		return true
	}
	for _, result := range resource.Results {
		if len(result.Checks) > 0 {
			return true
		}
	}
	return false
}

func isFailure(status string) bool {
	status = strings.ToUpper(strings.TrimSpace(status))
	return status == "" || status == "FAIL"
}

func formatSeveritySummary(counts map[string]int) string {
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	values := make([]string, 0, len(order))
	for _, severity := range order {
		if count := counts[severity]; count > 0 {
			values = append(values, fmt.Sprintf("%s: %d", severity, count))
		}
	}
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func singleLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
