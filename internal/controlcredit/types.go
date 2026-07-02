// Package controlcredit loads the private vdr-control-credit taxonomy that maps
// (machine-verified control x CWE class) -> deterministic Modified-metric
// credit. This milestone (CC1) only loads and exposes the taxonomy in memory
// and stamps the report header; the join/scoring engine is a later milestone.
//
// The taxonomy is opt-in. With no --taxonomy ref the loader returns a disabled
// taxonomy and the credit engine is inert. Any load/parse failure disables the
// engine LOUDLY (the caller logs an error and marks the header) rather than
// silently falling back, so "which table scored this" is never ambiguous.
package controlcredit

import "fmt"

// Tier labels for the loaded taxonomy, surfaced in the report header.
const (
	TierFull    = "full"    // the full private table
	TierSnippet = "snippet" // the public snippet bundle
)

// Status records the outcome of a load attempt, so the header can distinguish a
// deliberately-absent taxonomy from a loud load failure.
type Status string

const (
	StatusDisabled Status = "disabled" // no --taxonomy flag; engine inert by design
	StatusLoaded   Status = "loaded"   // taxonomy loaded and active
	StatusFailed   Status = "failed"   // a load/parse failure disabled the engine
)

// Control names the verification control a row depends on. Its predicate lives
// in the verification-sources profile (keyed by this name).
type Control struct {
	Name string `yaml:"name"`
}

// Counters describes which weaknesses a row counters. cweClasses holds a mix of
// literal CWE ids ("CWE-787") and class references ("class:ACE"); class
// references are expanded at load time.
type Counters struct {
	CWEClasses []string `yaml:"cweClasses"`
	Rationale  string   `yaml:"rationale"`
}

// Credit is the scoring move a row applies once its control is verified and its
// conditions hold. The join/scoring engine (later milestones) consumes it; CC1
// only carries it in memory.
type Credit struct {
	Lane           string   `yaml:"lane"`
	Metrics        []string `yaml:"metrics"`
	Move           string   `yaml:"move"`
	ResidualFactor float64  `yaml:"residualFactor,omitempty"`
	Conditions     []string `yaml:"conditions"`
	Disqualifiers  []string `yaml:"disqualifiers"`
}

// Provenance is the row's governance stamp inside the taxonomy.
type Provenance struct {
	Version int    `yaml:"version"`
	Status  string `yaml:"status"`
}

// Row is one taxonomy entry: a control that counters a set of CWEs and, when
// verified, applies a credit move.
type Row struct {
	ID         string     `yaml:"id"`
	Title      string     `yaml:"title"`
	Control    Control    `yaml:"control"`
	Counters   Counters   `yaml:"counters"`
	Credit     Credit     `yaml:"credit"`
	Confidence string     `yaml:"confidence"`
	Visibility string     `yaml:"visibility,omitempty"`
	Provenance Provenance `yaml:"provenance"`

	// expandedCWEs holds the row's unconditional counter set: literal CWEs plus
	// the members of any referenced class (ACE members, CRASH unconditional
	// members). Populated at load time.
	expandedCWEs []string
	// availabilityOnlyCWEs holds the extra CWEs a class:CRASH reference matches
	// only when the finding's own CVSS vector is availability-only. Kept separate
	// so the join engine can apply the per-finding condition later.
	availabilityOnlyCWEs []string
}

// CountersCWEs returns the effective counter set for a finding. When
// availabilityOnly is true (the finding's CVSS vector is C:N/I:N with A:L|H) the
// availability-only CRASH members are included.
func (r Row) CountersCWEs(availabilityOnly bool) []string {
	out := append([]string(nil), r.expandedCWEs...)
	if availabilityOnly {
		out = append(out, r.availabilityOnlyCWEs...)
	}
	return out
}

// UnconditionalCWEs returns the CWEs this row counters regardless of the
// finding's vector (class:ACE members, CRASH unconditional members, literals).
func (r Row) UnconditionalCWEs() []string {
	return append([]string(nil), r.expandedCWEs...)
}

// AvailabilityOnlyCWEs returns the CWEs this row counters only when the finding
// is availability-only (class:CRASH membersWhenAvailabilityOnly).
func (r Row) AvailabilityOnlyCWEs() []string {
	return append([]string(nil), r.availabilityOnlyCWEs...)
}

// Class is a curated CWE grouping keyed by exploitation outcome. CRASH carries a
// second, vector-conditioned member set.
type Class struct {
	Title                       string   `yaml:"title"`
	Members                     []string `yaml:"members"`
	MembersWhenAvailabilityOnly []string `yaml:"membersWhenAvailabilityOnly"`
	Notes                       string   `yaml:"notes,omitempty"`
}

// Expand returns the class's member CWEs. When availabilityOnly is true the
// vector-conditioned members (currently CRASH's membersWhenAvailabilityOnly) are
// appended.
func (c Class) Expand(availabilityOnly bool) []string {
	out := append([]string(nil), c.Members...)
	if availabilityOnly {
		out = append(out, c.MembersWhenAvailabilityOnly...)
	}
	return out
}

// VerificationSource maps a platform key (kubernetes, vm-systemd, aws-managed,
// gcp-managed, any, any-postgres, ...) to the predicate that proves the control
// is enforced on that platform.
type VerificationSource map[string]string

// Taxonomy is the loaded, in-memory control-credit table. A disabled taxonomy
// (no --taxonomy ref) carries no rows and the credit engine stays inert.
type Taxonomy struct {
	Enabled bool
	Status  Status
	// Ref is the --taxonomy value used (local path or owner/repo@tag).
	Ref string
	// Tier is "full" or "snippet"; surfaced in the report header.
	Tier string
	// Version is the taxonomy release (the pinned tag, or the CHANGELOG version
	// for a local path). Recorded in the header for reproducibility.
	Version string

	Rows                []Row
	Classes             map[string]Class
	VerificationSources map[string]VerificationSource
}

// Disabled returns an inert taxonomy: no rows, credit engine off. This is the
// default when --taxonomy is absent.
func Disabled() *Taxonomy {
	return &Taxonomy{Enabled: false, Status: StatusDisabled}
}

// failed returns a disabled taxonomy that records a loud load failure, so the
// header can say the engine was disabled by an error rather than by design.
func failed(ref string) *Taxonomy {
	return &Taxonomy{Enabled: false, Status: StatusFailed, Ref: ref}
}

// ExpandClass returns the member CWEs of the named class ("ACE", "CRASH"),
// including vector-conditioned members when availabilityOnly is true. Unknown
// class names return nil.
func (t *Taxonomy) ExpandClass(name string, availabilityOnly bool) []string {
	if t == nil {
		return nil
	}
	c, ok := t.Classes[name]
	if !ok {
		return nil
	}
	return c.Expand(availabilityOnly)
}

// ExpandCRASH returns the CRASH class members, adding the availability-only
// members when availabilityOnly is true.
func (t *Taxonomy) ExpandCRASH(availabilityOnly bool) []string {
	return t.ExpandClass("CRASH", availabilityOnly)
}

// HeaderLabel is the report-header tier/version stamp, e.g. "full-v0.8.0". A
// deliberately-absent taxonomy returns "" (nothing shown); a load failure
// returns "disabled (load failed)" so the loud failure is visible.
func (t *Taxonomy) HeaderLabel() string {
	if t == nil {
		return ""
	}
	switch t.Status {
	case StatusLoaded:
		return fmt.Sprintf("%s-v%s", t.Tier, t.Version)
	case StatusFailed:
		return "disabled (load failed)"
	default:
		return ""
	}
}
