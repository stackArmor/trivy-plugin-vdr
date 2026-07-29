package chaincatalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed data/catalog.json
var catalogFS embed.FS

var (
	builtinOnce    sync.Once
	builtinCatalog *Catalog
	builtinErr     error
)

// Catalog is an immutable lookup view over generated chain-taxonomy data.
type Catalog struct {
	data Data
}

// Builtin loads and validates the catalog embedded in the vdr binary.
func Builtin() (*Catalog, error) {
	builtinOnce.Do(func() {
		raw, err := catalogFS.ReadFile("data/catalog.json")
		if err != nil {
			builtinErr = fmt.Errorf("read embedded chain catalog: %w", err)
			return
		}
		builtinCatalog, builtinErr = Parse(raw)
	})
	return builtinCatalog, builtinErr
}

// Parse validates serialized catalog data and returns an immutable lookup view.
func Parse(raw []byte) (*Catalog, error) {
	var data Data
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("decode chain catalog: %w", err)
	}
	if data.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported chain catalog schema %q (want %q)", data.SchemaVersion, SchemaVersion)
	}
	if data.Patterns == nil || data.CWEs == nil {
		return nil, fmt.Errorf("chain catalog is missing pattern or CWE indexes")
	}
	for id, pattern := range data.Patterns {
		if normalizeCAPEC(id) != id {
			return nil, fmt.Errorf("chain catalog contains non-normalized pattern key %q", id)
		}
		if pattern.ID != id {
			return nil, fmt.Errorf("pattern key %s contains identifier %q", id, pattern.ID)
		}
		if pattern.Abstraction != "Standard" && pattern.Abstraction != "Detailed" {
			return nil, fmt.Errorf("pattern %s has ineligible abstraction %q", id, pattern.Abstraction)
		}
		status := strings.ToLower(strings.TrimSpace(pattern.Status))
		if status == "deprecated" || status == "obsolete" {
			return nil, fmt.Errorf("pattern %s has excluded status %q", id, pattern.Status)
		}
		for _, cwe := range pattern.CWEs {
			if normalizeCWE(cwe) != cwe {
				return nil, fmt.Errorf("pattern %s contains non-normalized CWE %q", id, cwe)
			}
			if !contains(data.CWEs[cwe], id) {
				return nil, fmt.Errorf("pattern %s CWE %s is missing from the reverse index", id, cwe)
			}
		}
		for _, predecessor := range pattern.Predecessors {
			other, ok := data.Patterns[predecessor]
			if !ok {
				return nil, fmt.Errorf("pattern %s references missing predecessor %s", id, predecessor)
			}
			if !contains(other.Successors, id) {
				return nil, fmt.Errorf("pattern %s predecessor %s lacks the reciprocal successor edge", id, predecessor)
			}
		}
		for _, successor := range pattern.Successors {
			other, ok := data.Patterns[successor]
			if !ok {
				return nil, fmt.Errorf("pattern %s references missing successor %s", id, successor)
			}
			if !contains(other.Predecessors, id) {
				return nil, fmt.Errorf("pattern %s successor %s lacks the reciprocal predecessor edge", id, successor)
			}
		}
	}
	for cwe, ids := range data.CWEs {
		if normalizeCWE(cwe) != cwe {
			return nil, fmt.Errorf("chain catalog contains non-normalized CWE key %q", cwe)
		}
		for _, id := range ids {
			pattern, ok := data.Patterns[id]
			if !ok {
				return nil, fmt.Errorf("CWE %s references missing pattern %s", cwe, id)
			}
			if !contains(pattern.CWEs, cwe) {
				return nil, fmt.Errorf("CWE %s references pattern %s without a reciprocal CWE entry", cwe, id)
			}
		}
	}
	return &Catalog{data: data}, nil
}

// Sources returns the upstream corpus provenance for this catalog.
func (c *Catalog) Sources() Sources {
	if c == nil {
		return Sources{}
	}
	return c.data.Sources
}

// Pattern returns one CAPEC pattern by normalized identifier.
func (c *Catalog) Pattern(id string) (Pattern, bool) {
	if c == nil {
		return Pattern{}, false
	}
	pattern, ok := c.data.Patterns[normalizeCAPEC(id)]
	return pattern, ok
}

// PatternsForCWEs returns the unique eligible CAPEC patterns associated with
// the supplied CWEs, sorted by CAPEC identifier.
func (c *Catalog) PatternsForCWEs(cwes []string) []Pattern {
	if c == nil || len(cwes) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, cwe := range cwes {
		for _, id := range c.data.CWEs[normalizeCWE(cwe)] {
			seen[id] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]Pattern, 0, len(ids))
	for _, id := range ids {
		result = append(result, c.data.Patterns[id])
	}
	return result
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

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
