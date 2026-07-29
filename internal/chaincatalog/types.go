// Package chaincatalog provides the generated, offline CAPEC-to-CWE and
// CAPEC-to-ATT&CK relationship catalog used by chain analysis.
package chaincatalog

const SchemaVersion = "1"

// Data is the serialized catalog embedded in the vdr binary.
type Data struct {
	SchemaVersion string              `json:"schemaVersion"`
	Sources       Sources             `json:"sources"`
	Patterns      map[string]Pattern  `json:"patterns"`
	CWEs          map[string][]string `json:"cwes"`
}

// Sources records the exact upstream corpus versions and content hashes used to
// generate a catalog. This makes every projected relationship reproducible.
type Sources struct {
	CAPECVersion  string `json:"capecVersion"`
	CAPECDate     string `json:"capecDate,omitempty"`
	CAPECSHA256   string `json:"capecSha256"`
	ATTACKVersion string `json:"attackVersion"`
	ATTACKDate    string `json:"attackDate,omitempty"`
	ATTACKSHA256  string `json:"attackSha256"`
}

// Pattern is one active Standard or Detailed CAPEC attack pattern.
type Pattern struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Abstraction   string          `json:"abstraction"`
	Status        string          `json:"status"`
	CWEs          []string        `json:"cwes,omitempty"`
	Techniques    []Technique     `json:"techniques,omitempty"`
	Predecessors  []string        `json:"predecessors,omitempty"`
	Successors    []string        `json:"successors,omitempty"`
	Consequences  []Consequence   `json:"consequences,omitempty"`
	Prerequisites []string        `json:"prerequisites,omitempty"`
	ExecutionFlow []ExecutionStep `json:"executionFlow,omitempty"`
}

// Technique is an ATT&CK technique referenced by a CAPEC taxonomy mapping.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Tactics []string `json:"tactics,omitempty"`
}

// Consequence preserves the structured CAPEC scope, impact, and note fields.
type Consequence struct {
	Scopes []string `json:"scopes,omitempty"`
	Impact string   `json:"impact,omitempty"`
	Note   string   `json:"note,omitempty"`
}

// ExecutionStep preserves CAPEC's typed Explore/Experiment/Exploit flow.
type ExecutionStep struct {
	Step        string   `json:"step,omitempty"`
	Phase       string   `json:"phase,omitempty"`
	Description string   `json:"description,omitempty"`
	Techniques  []string `json:"techniques,omitempty"`
}
