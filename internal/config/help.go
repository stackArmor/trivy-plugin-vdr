package config

import (
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type helpSection struct {
	title string
	flags []string
}

func printHelp(fs *flag.FlagSet, source string) {
	if source == "" {
		printRootHelp(fs)
		return
	}

	helpFprintf(fs.Output(), "%s\n\nUsage:\n  %s\n\nExamples:\n%s\n",
		sourceDescription(source), sourceUsage(source), sourceExamples(source))
	if note := sourceHelpNote(source); note != "" {
		helpFprintln(fs.Output(), "\nPrivate registries:")
		for _, line := range wrapHelpText(note, 76) {
			helpFprintf(fs.Output(), "  %s\n", line)
		}
		helpFprintln(fs.Output())
	}
	printHelpSections(fs, source, sourceHelpSections(source))
	helpFprintln(fs.Output(), "Run 'vdr --help' to see all sources and common examples.")
}

func printRootHelp(fs *flag.FlagSet) {
	helpFprint(fs.Output(), `Inventory deployment sources, scan their container images with Trivy, and report vulnerability risk.

Usage:
  vdr <source> [flags]
  vdr image [flags] IMAGE...
  vdr helm [flags] CHART
  vdr enrich-report --input REPORT.json [--output ENRICHED.json]

Sources:
  k8s       Scan workloads and container vulnerabilities in the current Kubernetes context
  k8s-compliance  Scan Kubernetes resources with Trivy's built-in compliance rules
  cloudrun  Scan Cloud Run services and jobs in a Google Cloud project
  ecs       Scan active AWS ECS task definitions
  image     Scan one or more container image references
  helm      Render and scan a Helm chart without a live cluster

Post-processing:
  enrich-report  Add embedded CAPEC/ATT&CK taxonomy evidence to a VDR JSON report

Examples:
  vdr k8s -n default --format table
  vdr k8s --all-namespaces --min-severity HIGH --output vdr-k8s.json
  vdr k8s-compliance -n default
  vdr k8s-compliance --all-namespaces --format json --output compliance.json
  vdr cloudrun --project my-project --region us-east4 --reachability-only
  vdr ecs --region us-east-1 --region us-west-2 --output vdr-ecs.json
  vdr image nginx:1.25 ghcr.io/acme/api:v2
  vdr helm ./charts/app -f values/prod.yaml --format json
  vdr enrich-report --input vdr.json --output vdr-enriched.json

`)
	printHelpSections(fs, "", []helpSection{{
		title: "Common flags",
		flags: []string{"format", "view", "no-dedupe", "output", "timeout", "quiet", "debug"},
	}})
	helpFprintln(fs.Output(), "Run 'vdr <source> --help' for source-specific flags and examples.")
	helpFprintln(fs.Output(), "For the helm source, -f means --values; use --format for the report format.")
}

func sourceDescription(source string) string {
	switch source {
	case SourceK8s:
		return "Inventory and scan workloads from the current Kubernetes context."
	case SourceK8sCompliance:
		return "Scan Kubernetes resource definitions with Trivy's built-in misconfiguration and RBAC rules."
	case SourceCloudRun:
		return "Inventory and scan Cloud Run services and jobs in selected regions."
	case SourceECS:
		return "Inventory and scan active AWS ECS task definitions in selected regions."
	case SourceImage:
		return "Scan one or more container image references directly."
	case SourceHelm:
		return "Render a Helm chart, inventory its workloads, and scan their images without a live cluster."
	default:
		return ""
	}
}

func sourceUsage(source string) string {
	switch source {
	case SourceK8sCompliance:
		return "vdr k8s-compliance [flags]"
	case SourceCloudRun:
		return "vdr cloudrun --project PROJECT --region REGION [flags]"
	case SourceECS:
		return "vdr ecs --region REGION [flags]"
	case SourceImage:
		return "vdr image [flags] IMAGE..."
	case SourceHelm:
		return "vdr helm [flags] CHART"
	default:
		return "vdr k8s [flags]"
	}
}

func sourceExamples(source string) string {
	switch source {
	case SourceK8s:
		return `  vdr k8s -n default --format table
  vdr k8s --all-namespaces --min-severity HIGH --output vdr-k8s.json
  vdr k8s --all-namespaces --sip-config-map ./vdr-fedramp.yaml --reachability-only --output reachability.json`
	case SourceK8sCompliance:
		return `  vdr k8s-compliance -n default
  vdr k8s-compliance --all-namespaces --min-severity HIGH
  vdr k8s-compliance --all-namespaces --format json --output compliance.json`
	case SourceCloudRun:
		return `  vdr cloudrun --project my-project --region us-east4
  vdr cloudrun --project my-project --region us-east4 --region us-central1 --output cloudrun.json
  vdr cloudrun --project my-project --region us-east4 --reachability-only --view resources`
	case SourceECS:
		return `  vdr ecs --region us-east-1
  vdr ecs --region us-east-1 --region us-west-2 --output ecs.json
  vdr ecs --region us-gov-west-1 --scan-reachability-only --format table`
	case SourceImage:
		return `  vdr image nginx:1.25
  vdr image --parallel-scans 2 nginx:1.25 ghcr.io/acme/api:v2
  vdr image --min-severity HIGH -O registry.example.com/team/app:v1`
	case SourceHelm:
		return `  vdr helm ./charts/app -f values/base.yaml -f values/prod.yaml --format json
  vdr helm bitnami/nginx --chart-version 19.0.0 --namespace prod
  vdr helm ./charts/app --ingress-chart ./charts/edge --ingress-values values/edge.yaml`
	default:
		return ""
	}
}

func sourceHelpNote(source string) string {
	switch source {
	case SourceK8s:
		return "Credentials are loaded automatically from workload imagePullSecrets and the local Docker config."
	case SourceK8sCompliance:
		return ""
	case SourceHelm:
		return "Credentials are loaded automatically from rendered imagePullSecrets and the local Docker config."
	case SourceECS:
		return "Credentials are loaded automatically from ECS repository credentials, the local Docker config, and supported cloud CLIs."
	case SourceCloudRun, SourceImage:
		return "Credentials are loaded automatically from the local Docker config and supported cloud CLIs."
	default:
		return ""
	}
}

func sourceHelpSections(source string) []helpSection {
	sections := make([]helpSection, 0, 10)
	switch source {
	case SourceK8s:
		sections = append(sections, helpSection{
			title: "Kubernetes source",
			flags: []string{"namespace", "all-namespaces", "include-zero-daemonsets", "sip-config-map", "context-name"},
		})
	case SourceK8sCompliance:
		return []helpSection{
			{
				title: "Kubernetes compliance scan",
				flags: []string{"namespace", "all-namespaces", "min-severity", "timeout", "cache-dir", "context-name"},
			},
			{
				title: "Report output",
				flags: []string{"format", "output"},
			},
			{
				title: "Logging",
				flags: []string{"quiet", "debug"},
			},
		}
	case SourceCloudRun:
		sections = append(sections, helpSection{
			title: "Cloud Run source",
			flags: []string{"project", "region"},
		})
	case SourceECS:
		sections = append(sections, helpSection{
			title: "ECS source",
			flags: []string{"region"},
		})
	case SourceHelm:
		sections = append(sections,
			helpSection{
				title: "Application chart",
				flags: []string{"values", "release-name", "namespace", "chart-version", "repo", "config-map"},
			},
			helpSection{
				title: "Ingress and Gateway chart",
				flags: []string{"ingress-chart", "ingress-values", "ingress-release-name", "ingress-namespace", "ingress-chart-version", "ingress-repo"},
			},
			helpSection{
				title: "Helm rendering",
				flags: []string{"kube-version", "api-versions", "include-crds"},
			},
		)
	}

	if source != SourceImage {
		sections = append(sections, helpSection{
			title: "Exposure and scan modes",
			flags: []string{"reachability-only", "scan-reachability-only", "skip-exposure"},
		})
	}

	sections = append(sections,
		helpSection{
			title: "Vulnerability scanning",
			flags: []string{"image-src", "parallel-scans", "timeout"},
		},
		helpSection{
			title: "Filtering, enrichment, and scoring",
			flags: []string{"min-severity", "min-epss", "skip-enrichment", "refresh-enrichment", "include-chain-taxonomy", "scoring-config", "security-requirements-ceiling"},
		},
		helpSection{
			title: "Registry authentication and VEX",
			flags: []string{"skip-registry-auth", "no-gcloud-auth", "no-ecr-auth", "gcp-impersonate-service-account", "aws-role-arn", "oci-vex-included", "vex-oci-registries"},
		},
		helpSection{
			title: "Cache management",
			flags: []string{"cache-dir", "cache-cleanup", "cache-min-free-gb", "cache-min-free-percent"},
		},
		helpSection{
			title: "Report output",
			flags: []string{"format", "view", "no-dedupe", "output", "html-output", "html-template"},
		},
		helpSection{
			title: "Logging",
			flags: []string{"quiet", "debug"},
		},
	)
	return sections
}

func printHelpSections(fs *flag.FlagSet, source string, sections []helpSection) {
	for _, section := range sections {
		helpFprintf(fs.Output(), "%s:\n", section.title)
		for _, name := range section.flags {
			printHelpFlag(fs, source, name)
		}
		helpFprintln(fs.Output())
	}
}

func printHelpFlag(fs *flag.FlagSet, source, name string) {
	f := fs.Lookup(name)
	if f == nil {
		return
	}

	var names []string
	if alias := helpAlias(source, name); alias != "" {
		names = append(names, "-"+alias)
	}
	longName := "--" + name
	if valueName := helpValueName(name); valueName != "" && !isBoolFlag(f) {
		longName += " " + valueName
	}
	names = append(names, longName)
	helpFprintf(fs.Output(), "  %s\n", strings.Join(names, ", "))

	description := f.Usage + helpDefault(f)
	if source == SourceK8sCompliance && name == "format" {
		description = "output format: table or json (default \"table\")"
	}
	for _, line := range wrapHelpText(description, 74) {
		helpFprintf(fs.Output(), "      %s\n", line)
	}
}

// FlagSet.Usage cannot return an output error, so help rendering deliberately
// ignores writer failures while keeping that decision explicit for linters.
func helpFprint(w io.Writer, value string) {
	_, _ = fmt.Fprint(w, value)
}

func helpFprintf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func helpFprintln(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}

func helpAlias(source, name string) string {
	switch name {
	case "namespace":
		return "n"
	case "output":
		return "o"
	case "format":
		if source != SourceHelm {
			return "f"
		}
	case "values":
		if source == SourceHelm {
			return "f"
		}
	case "quiet":
		return "q"
	case "timeout":
		return "t"
	case "oci-vex-included":
		return "O"
	}
	return ""
}

func helpValueName(name string) string {
	valueNames := map[string]string{
		"api-versions":                    "VERSION",
		"aws-role-arn":                    "ARN",
		"cache-cleanup":                   "POLICY",
		"cache-dir":                       "DIR",
		"cache-min-free-gb":               "GB",
		"cache-min-free-percent":          "PERCENT",
		"chart-version":                   "VERSION",
		"config-map":                      "FILE",
		"sip-config-map":                  "FILE",
		"format":                          "FORMAT",
		"gcp-impersonate-service-account": "EMAIL",
		"html-output":                     "FILE",
		"html-template":                   "FILE",
		"image-src":                       "SOURCE",
		"ingress-chart":                   "CHART",
		"ingress-chart-version":           "VERSION",
		"ingress-namespace":               "NAMESPACE",
		"ingress-release-name":            "NAME",
		"ingress-repo":                    "URL",
		"ingress-values":                  "FILE",
		"kube-version":                    "VERSION",
		"min-epss":                        "SCORE",
		"min-severity":                    "SEVERITY",
		"namespace":                       "NAMESPACE",
		"output":                          "FILE",
		"parallel-scans":                  "N",
		"project":                         "PROJECT",
		"region":                          "REGION",
		"release-name":                    "NAME",
		"repo":                            "URL",
		"scoring-config":                  "FILE",
		"security-requirements-ceiling":   "VECTOR",
		"timeout":                         "DURATION",
		"values":                          "FILE",
		"vex-oci-registries":              "PREFIXES",
		"view":                            "VIEW",
	}
	return valueNames[name]
}

func helpDefault(f *flag.Flag) string {
	switch f.DefValue {
	case "", "false", "0", "[]":
		return ""
	}
	if getter, ok := f.Value.(flag.Getter); ok {
		if _, ok := getter.Get().(string); ok {
			return " (default " + strconv.Quote(f.DefValue) + ")"
		}
	}
	return " (default " + f.DefValue + ")"
}

func wrapHelpText(value string, width int) []string {
	words := strings.Fields(value)
	if len(words) == 0 {
		return nil
	}
	lines := make([]string, 0, len(words)/8+1)
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = word
			continue
		}
		line += " " + word
	}
	return append(lines, line)
}
