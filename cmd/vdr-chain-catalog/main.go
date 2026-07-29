// Command vdr-chain-catalog builds the offline chain-taxonomy catalog embedded
// in the vdr plugin. It parses the official CAPEC XML and ATT&CK STIX JSON
// directly; it does not consume a third-party mapping.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/chaincatalog"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "vdr-chain-catalog: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("vdr-chain-catalog", flag.ContinueOnError)
	flags.SetOutput(stdout)
	var capecPath string
	var attackPath string
	var outputPath string
	flags.StringVar(&capecPath, "capec", "", "path to capec_latest.zip or the CAPEC XML")
	flags.StringVar(&attackPath, "attack", "", "path to the Enterprise ATT&CK STIX JSON")
	flags.StringVar(&outputPath, "output", "", "catalog JSON output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if capecPath == "" || attackPath == "" || outputPath == "" {
		return errors.New("--capec, --attack, and --output are required")
	}

	capecXML, err := readCAPEC(capecPath)
	if err != nil {
		return err
	}
	attackJSON, err := os.ReadFile(attackPath)
	if err != nil {
		return fmt.Errorf("read ATT&CK STIX: %w", err)
	}

	data, stats, err := buildCatalog(capecXML, attackJSON)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode catalog: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
		return fmt.Errorf("write catalog: %w", err)
	}

	fmt.Fprintf(stdout, "wrote %s: %d patterns, %d CWE keys, %d ATT&CK mappings, %d chain edges\n",
		outputPath, stats.Patterns, stats.CWEs, stats.ATTACKMappings, stats.ChainEdges)
	return nil
}

type buildStats struct {
	Patterns       int
	CWEs           int
	ATTACKMappings int
	ChainEdges     int
}

type capecCatalogXML struct {
	Version  string            `xml:"Version,attr"`
	Date     string            `xml:"Date,attr"`
	Patterns []capecPatternXML `xml:"Attack_Patterns>Attack_Pattern"`
}

type capecPatternXML struct {
	ID          string `xml:"ID,attr"`
	Name        string `xml:"Name,attr"`
	Abstraction string `xml:"Abstraction,attr"`
	Status      string `xml:"Status,attr"`

	RelatedWeaknesses []struct {
		CWEID string `xml:"CWE_ID,attr"`
	} `xml:"Related_Weaknesses>Related_Weakness"`

	TaxonomyMappings []struct {
		TaxonomyName string `xml:"Taxonomy_Name,attr"`
		EntryID      string `xml:"Entry_ID"`
		EntryName    string `xml:"Entry_Name"`
	} `xml:"Taxonomy_Mappings>Taxonomy_Mapping"`

	RelatedPatterns []struct {
		Nature  string `xml:"Nature,attr"`
		CAPECID string `xml:"CAPEC_ID,attr"`
	} `xml:"Related_Attack_Patterns>Related_Attack_Pattern"`

	Consequences []struct {
		Scopes []string       `xml:"Scope"`
		Impact string         `xml:"Impact"`
		Note   structuredText `xml:"Note"`
	} `xml:"Consequences>Consequence"`

	Prerequisites []structuredText `xml:"Prerequisites>Prerequisite"`

	ExecutionSteps []struct {
		Step        string           `xml:"Step"`
		Phase       string           `xml:"Phase"`
		Description structuredText   `xml:"Description"`
		Techniques  []structuredText `xml:"Technique"`
	} `xml:"Execution_Flow>Attack_Step"`
}

type structuredText string

func (s *structuredText) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	var raw struct {
		Inner string `xml:",innerxml"`
	}
	if err := decoder.DecodeElement(&raw, &start); err != nil {
		return err
	}
	*s = structuredText(cleanStructuredText(raw.Inner))
	return nil
}

type attackBundle struct {
	Objects []attackObject `json:"objects"`
}

type attackObject struct {
	Type               string `json:"type"`
	Name               string `json:"name"`
	Modified           string `json:"modified"`
	Revoked            bool   `json:"revoked"`
	Deprecated         bool   `json:"x_mitre_deprecated"`
	MITREVersion       string `json:"x_mitre_version"`
	ExternalReferences []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
	KillChainPhases []struct {
		PhaseName string `json:"phase_name"`
	} `json:"kill_chain_phases"`
}

type attackTechnique struct {
	Name    string
	Tactics []string
}

func buildCatalog(capecXML, attackJSON []byte) (chaincatalog.Data, buildStats, error) {
	var capec capecCatalogXML
	if err := xml.Unmarshal(capecXML, &capec); err != nil {
		return chaincatalog.Data{}, buildStats{}, fmt.Errorf("decode CAPEC XML: %w", err)
	}
	if capec.Version == "" {
		return chaincatalog.Data{}, buildStats{}, errors.New("CAPEC XML has no catalog version")
	}

	techniques, attackVersion, attackDate, err := parseATTACK(attackJSON)
	if err != nil {
		return chaincatalog.Data{}, buildStats{}, err
	}

	data := chaincatalog.Data{
		SchemaVersion: chaincatalog.SchemaVersion,
		Sources: chaincatalog.Sources{
			CAPECVersion:  capec.Version,
			CAPECDate:     capec.Date,
			CAPECSHA256:   sha256Hex(capecXML),
			ATTACKVersion: attackVersion,
			ATTACKDate:    attackDate,
			ATTACKSHA256:  sha256Hex(attackJSON),
		},
		Patterns: map[string]chaincatalog.Pattern{},
		CWEs:     map[string][]string{},
	}

	rawByID := map[string]capecPatternXML{}
	for _, source := range capec.Patterns {
		if !eligiblePattern(source) {
			continue
		}
		id := normalizeCAPEC(source.ID)
		rawByID[id] = source
		data.Patterns[id] = convertPattern(source, techniques)
	}

	edgeSet := map[string]struct{}{}
	for id, source := range rawByID {
		pattern := data.Patterns[id]
		for _, relation := range source.RelatedPatterns {
			target := normalizeCAPEC(relation.CAPECID)
			if _, ok := data.Patterns[target]; !ok {
				continue
			}
			var from, to string
			switch strings.ToLower(strings.TrimSpace(relation.Nature)) {
			case "canprecede":
				from, to = id, target
			case "canfollow":
				from, to = target, id
			default:
				continue
			}
			edgeSet[from+"\x00"+to] = struct{}{}
		}
		data.Patterns[id] = pattern
	}
	for edge := range edgeSet {
		from, to, _ := strings.Cut(edge, "\x00")
		source := data.Patterns[from]
		source.Successors = append(source.Successors, to)
		data.Patterns[from] = source
		target := data.Patterns[to]
		target.Predecessors = append(target.Predecessors, from)
		data.Patterns[to] = target
	}

	attackMappingCount := 0
	for id, pattern := range data.Patterns {
		pattern.CWEs = sortedUnique(pattern.CWEs)
		pattern.Predecessors = sortedUnique(pattern.Predecessors)
		pattern.Successors = sortedUnique(pattern.Successors)
		sort.Slice(pattern.Techniques, func(i, j int) bool {
			return pattern.Techniques[i].ID < pattern.Techniques[j].ID
		})
		attackMappingCount += len(pattern.Techniques)
		data.Patterns[id] = pattern
		for _, cwe := range pattern.CWEs {
			data.CWEs[cwe] = append(data.CWEs[cwe], id)
		}
	}
	for cwe, ids := range data.CWEs {
		data.CWEs[cwe] = sortedUnique(ids)
	}

	stats := buildStats{
		Patterns:       len(data.Patterns),
		CWEs:           len(data.CWEs),
		ATTACKMappings: attackMappingCount,
		ChainEdges:     len(edgeSet),
	}
	return data, stats, nil
}

func parseATTACK(raw []byte) (map[string]attackTechnique, string, string, error) {
	var bundle attackBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, "", "", fmt.Errorf("decode ATT&CK STIX: %w", err)
	}
	result := map[string]attackTechnique{}
	var version string
	var date string
	for _, object := range bundle.Objects {
		if object.Type == "x-mitre-collection" && object.Name == "Enterprise ATT&CK" {
			version = object.MITREVersion
			date = object.Modified
			continue
		}
		if object.Type != "attack-pattern" || object.Revoked || object.Deprecated {
			continue
		}
		id := ""
		for _, reference := range object.ExternalReferences {
			if reference.SourceName == "mitre-attack" && strings.HasPrefix(reference.ExternalID, "T") {
				id = strings.ToUpper(strings.TrimSpace(reference.ExternalID))
				break
			}
		}
		if id == "" {
			continue
		}
		tactics := make([]string, 0, len(object.KillChainPhases))
		for _, phase := range object.KillChainPhases {
			if value := strings.TrimSpace(phase.PhaseName); value != "" {
				tactics = append(tactics, value)
			}
		}
		result[id] = attackTechnique{Name: object.Name, Tactics: sortedUnique(tactics)}
	}
	if version == "" {
		return nil, "", "", errors.New("ATT&CK STIX has no Enterprise ATT&CK collection version")
	}
	return result, version, date, nil
}

func convertPattern(source capecPatternXML, attack map[string]attackTechnique) chaincatalog.Pattern {
	pattern := chaincatalog.Pattern{
		ID:          normalizeCAPEC(source.ID),
		Name:        strings.TrimSpace(source.Name),
		Abstraction: strings.TrimSpace(source.Abstraction),
		Status:      strings.TrimSpace(source.Status),
	}
	for _, weakness := range source.RelatedWeaknesses {
		if cwe := normalizeCWE(weakness.CWEID); cwe != "" {
			pattern.CWEs = append(pattern.CWEs, cwe)
		}
	}
	for _, mapping := range source.TaxonomyMappings {
		if !strings.EqualFold(strings.TrimSpace(mapping.TaxonomyName), "ATTACK") {
			continue
		}
		id := normalizeATTACK(mapping.EntryID)
		if id == "" {
			continue
		}
		technique := chaincatalog.Technique{
			ID:   id,
			Name: strings.TrimSpace(mapping.EntryName),
		}
		if current, ok := attack[id]; ok {
			technique.Name = current.Name
			technique.Tactics = append([]string(nil), current.Tactics...)
		}
		pattern.Techniques = append(pattern.Techniques, technique)
	}
	for _, consequence := range source.Consequences {
		value := chaincatalog.Consequence{
			Scopes: sortedUnique(trimmed(consequence.Scopes)),
			Impact: strings.TrimSpace(consequence.Impact),
			Note:   strings.TrimSpace(string(consequence.Note)),
		}
		if len(value.Scopes) > 0 || value.Impact != "" || value.Note != "" {
			pattern.Consequences = append(pattern.Consequences, value)
		}
	}
	for _, prerequisite := range source.Prerequisites {
		if value := strings.TrimSpace(string(prerequisite)); value != "" {
			pattern.Prerequisites = append(pattern.Prerequisites, value)
		}
	}
	pattern.Prerequisites = sortedUnique(pattern.Prerequisites)
	for _, step := range source.ExecutionSteps {
		value := chaincatalog.ExecutionStep{
			Step:        strings.TrimSpace(step.Step),
			Phase:       strings.TrimSpace(step.Phase),
			Description: strings.TrimSpace(string(step.Description)),
		}
		for _, technique := range step.Techniques {
			if text := strings.TrimSpace(string(technique)); text != "" {
				value.Techniques = append(value.Techniques, text)
			}
		}
		value.Techniques = sortedUnique(value.Techniques)
		pattern.ExecutionFlow = append(pattern.ExecutionFlow, value)
	}
	return pattern
}

func eligiblePattern(pattern capecPatternXML) bool {
	abstraction := strings.ToLower(strings.TrimSpace(pattern.Abstraction))
	if abstraction != "standard" && abstraction != "detailed" {
		return false
	}
	status := strings.ToLower(strings.TrimSpace(pattern.Status))
	return status != "deprecated" && status != "obsolete"
}

func readCAPEC(path string) ([]byte, error) {
	if !strings.HasSuffix(strings.ToLower(path), ".zip") {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read CAPEC XML: %w", err)
		}
		return data, nil
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open CAPEC archive: %w", err)
	}
	defer archive.Close()
	for _, file := range archive.File {
		name := strings.ToLower(filepath.Base(file.Name))
		if !strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".xsd.xml") {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open CAPEC XML in archive: %w", err)
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read CAPEC XML in archive: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close CAPEC XML in archive: %w", closeErr)
		}
		return data, nil
	}
	return nil, errors.New("CAPEC archive contains no XML catalog")
}

var (
	tagPattern         = regexp.MustCompile(`<[^>]+>`)
	spacePattern       = regexp.MustCompile(`\s+`)
	punctuationPattern = regexp.MustCompile(`\s+([.,;:!?])`)
)

func cleanStructuredText(value string) string {
	value = strings.ReplaceAll(value, "<BR/>", " ")
	value = strings.ReplaceAll(value, "<br/>", " ")
	value = tagPattern.ReplaceAllString(value, " ")
	value = html.UnescapeString(value)
	value = spacePattern.ReplaceAllString(value, " ")
	value = punctuationPattern.ReplaceAllString(value, "$1")
	return strings.TrimSpace(value)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func normalizeCWE(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "CWE-") {
		value = "CWE-" + value
	}
	return value
}

func normalizeCAPEC(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "CAPEC-") {
		value = "CAPEC-" + value
	}
	return value
}

func normalizeATTACK(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "T") {
		value = "T" + value
	}
	return value
}

func trimmed(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
