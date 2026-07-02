package controlcredit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

// StackingFloor caps the total stacked exploitability reduction: adjustedEPSS is
// never lowered below EPSS * StackingFloor no matter how many residual factors
// apply. It is a governed constant (like the PAIN cut-points), back-test pending.
const StackingFloor = 0.5

// Lane values on a taxonomy row's credit.
const (
	laneImpact     = "impact"
	laneLikelihood = "likelihood"
)

// Credit moves on the likelihood lane.
const (
	moveEPSSResidual = "epss-residual"
	moveFloorDefeat  = "floor-defeated"
)

// wildcardCWE marks a likelihood row that counters every CWE.
const wildcardCWE = "*"

// JoinInput is one (finding, asset) pair fed to the credit engine.
type JoinInput struct {
	CWEs              []string
	CVSSVector        string
	EPSS              float64 // < 0 = unknown
	KEV               bool    // active exploitation / CISA KEV; frozen (no residual, LEV stays true)
	InternetReachable bool
	// Verified is the per-control verification map for the asset (VerifyControls).
	Verified map[string]VerificationResult
	// LEVThreshold is the EPSS score at/above which a finding is LEV (scoring config).
	LEVThreshold float64
}

// NearMiss records a row that keyed a finding but did not fire, with the exact
// blocker, for the CC4 credit-posture report (populated here, surfaced later).
type NearMiss struct {
	RowID  string
	Reason string
}

// JoinResult is the collapsed credit decision for one (finding, asset).
type JoinResult struct {
	// Impact-lane result: which Modified metrics move High->Low (collapsed, no
	// stacking) plus the firing rows.
	MC, MI, MA bool
	Credits    []model.ControlCredit
	NearMisses []NearMiss

	// Likelihood-lane result.
	Exploitability model.ExploitabilityAdjustment
	// LEV is the recomputed Likely-Exploitable verdict using adjustedEPSS with KEV
	// frozen and the edge-auth floor-defeat term.
	LEV bool
}

// Join runs the credit engine for one (finding, asset): the impact-lane join
// (CC3) and the exploitability adjustment (CC3b). A disabled taxonomy returns the
// zero result and LEV computed from the stock inputs, so callers can rely on it,
// but callers should skip Join entirely when no taxonomy is loaded to keep
// scoring byte-identical.
func (t *Taxonomy) Join(in JoinInput) JoinResult {
	var res JoinResult
	res.Exploitability = model.ExploitabilityAdjustment{EPSS: in.EPSS, AdjustedEPSS: in.EPSS}
	if t == nil || !t.Enabled {
		res.LEV = stockLEV(in)
		return res
	}

	availabilityOnly := isAvailabilityOnly(in.CVSSVector)
	cweSet := toSet(in.CWEs)

	// Impact lane.
	for i := range t.Rows {
		row := t.Rows[i]
		if row.Credit.Lane != laneImpact {
			continue
		}
		matched, viaClass := matchRow(row, cweSet, availabilityOnly)
		if !matched {
			continue
		}
		vr := in.Verified[row.Control.Name]
		if !vr.Verified {
			reason := vr.FailedPredicate
			if reason == "" {
				reason = fmt.Sprintf("control %q not verified", row.Control.Name)
			}
			res.NearMisses = append(res.NearMisses, NearMiss{RowID: row.ID, Reason: reason})
			continue
		}
		if met, why := impactConditionsMet(row, in); !met {
			res.NearMisses = append(res.NearMisses, NearMiss{RowID: row.ID, Reason: why})
			continue
		}
		// Fires. Collapse per metric (no stacking, GOVERNANCE 4a): the booleans
		// simply stay set; every firing row is still listed in evidence.
		for _, m := range row.Credit.Metrics {
			switch strings.ToUpper(strings.TrimSpace(m)) {
			case "MC":
				res.MC = true
			case "MI":
				res.MI = true
			case "MA":
				res.MA = true
			}
		}
		res.Credits = append(res.Credits, model.ControlCredit{
			RowID:           row.ID,
			TaxonomyVersion: t.Version,
			Metrics:         append([]string(nil), row.Credit.Metrics...),
			ViaClass:        viaClass,
			Evidence:        []string{impactEvidence(row, t.Version, viaClass, vr.Evidence)},
		})
	}
	sortCredits(res.Credits)

	// Likelihood lane (exploitability).
	res.Exploitability, res.LEV = t.exploitability(in)
	// Record whether the adjustment flipped the LEV verdict (LEV -> NLEV), for the
	// credit-posture report. KEV is frozen (stock LEV stays true), so it never lowers.
	res.Exploitability.LoweredLEV = stockLEV(in) && !res.LEV
	return res
}

// exploitability computes adjustedEPSS and the recomputed LEV. KEV is frozen: no
// residual applies, LEV stays true, the published EPSS is echoed unchanged.
func (t *Taxonomy) exploitability(in JoinInput) (model.ExploitabilityAdjustment, bool) {
	adj := model.ExploitabilityAdjustment{EPSS: in.EPSS, AdjustedEPSS: in.EPSS}

	if in.KEV {
		adj.KEVFrozen = true
		return adj, true // KEV => LEV, clock untouched, no residual
	}

	cweSet := toSet(in.CWEs)
	product := 1.0
	var rowIDs []string
	floorDefeated := false

	for i := range t.Rows {
		row := t.Rows[i]
		if row.Credit.Lane != laneLikelihood {
			continue
		}
		if !likelihoodMatches(row, cweSet) {
			continue
		}
		vr := in.Verified[row.Control.Name]
		if !vr.Verified {
			continue
		}
		switch row.Credit.Move {
		case moveEPSSResidual:
			f := row.Credit.ResidualFactor
			if f > 0 && f < 1 {
				product *= f // stacks multiplicatively (defense-in-depth)
				rowIDs = append(rowIDs, row.ID)
			}
		case moveFloorDefeat:
			floorDefeated = true
			rowIDs = append(rowIDs, row.ID)
		}
	}

	if in.EPSS >= 0 && len(rowIDs) > 0 && product < 1 {
		adj.AdjustedEPSS = maxFloat(in.EPSS*product, in.EPSS*StackingFloor)
	}
	adj.FloorDefeated = floorDefeated
	sort.Strings(rowIDs)
	adj.RowIDs = rowIDs

	// LEV = KEV OR (adjustedEPSS >= threshold) OR (automation-floor AND NOT
	// floor-defeated). The FRD-LEV automation floor is not modeled in v1
	// reachability (handoff decision 2), so the floor OR-term is inert here; the
	// floor-defeat row is still recorded on the adjustment for the CC4 report.
	lev := in.EPSS >= 0 && adj.AdjustedEPSS >= in.LEVThreshold
	return adj, lev
}

// stockLEV mirrors scoring.isLEV for the disabled-taxonomy path: active
// exploitation, or EPSS at/above the threshold.
func stockLEV(in JoinInput) bool {
	if in.KEV {
		return true
	}
	return in.EPSS >= 0 && in.EPSS >= in.LEVThreshold
}

// matchRow reports whether the finding's CWEs hit an impact row and, when the hit
// came through a class reference, which class (for the credit's viaClass field).
// Literal-member matches take precedence and carry no viaClass; a match found
// only among class-expanded members is attributed to the row's class reference.
func matchRow(row Row, cweSet map[string]bool, availabilityOnly bool) (bool, string) {
	literals := toSet(row.expandedCWEsLiteral())
	for cwe := range literals {
		if cweSet[cwe] {
			return true, ""
		}
	}
	for _, cwe := range row.CountersCWEs(availabilityOnly) {
		if cweSet[normCWE(cwe)] && !literals[normCWE(cwe)] {
			return true, firstClassRef(row)
		}
	}
	return false, ""
}

// firstClassRef returns the row's first class reference (e.g. "class:ACE").
func firstClassRef(row Row) string {
	for _, ref := range row.Counters.CWEClasses {
		if strings.HasPrefix(ref, classPrefix) {
			return ref
		}
	}
	return ""
}

// likelihoodMatches reports whether a likelihood row counters the finding: a "*"
// wildcard matches everything, otherwise any literal CWE overlap.
func likelihoodMatches(row Row, cweSet map[string]bool) bool {
	for _, ref := range row.Counters.CWEClasses {
		if ref == wildcardCWE {
			return true
		}
	}
	for _, cwe := range row.expandedCWEs {
		if cweSet[normCWE(cwe)] {
			return true
		}
	}
	return false
}

// impactConditionsMet evaluates the machine-checkable conditions for the rows
// this milestone can fire. Rows with no extra condition beyond their control's
// predicate pass; rows with a condition we cannot evaluate are conservatively
// blocked (no credit), and the near-miss names the gap.
func impactConditionsMet(row Row, in JoinInput) (bool, string) {
	switch row.ID {
	case "CC-RUN-ROFS":
		// The writable-path condition is folded into readonly-rootfs verification.
		return true, ""
	case "CC-RUN-NOSECRETS-ENV", "CC-NET-EGRESS-DENY", "CC-NET-IMDS-PROTECT":
		// Conditions restate the control predicate, already machine-verified.
		return true, ""
	case "CC-HA-LEAK":
		// "liveness/health checks configured" — folded into verified-ha.
		return true, ""
	case "CC-HA-RECOVERABLE-CRASH":
		// Reachability condition. Under v1 (no per-finding IRV) treat the finding
		// conservatively as IRV, so HA credit requires the rate-limit conjunction
		// (handoff). route-rate-limit is not collected in CC2, so this blocks.
		if in.Verified["route-rate-limit"].Verified {
			return true, ""
		}
		return false, "IRV-conservative HA: requires verified route-rate-limit on tainted routes (v1 reachability); route-rate-limit not verified"
	default:
		if len(row.Credit.Conditions) == 0 {
			return true, ""
		}
		return false, fmt.Sprintf("row %q has conditions not machine-evaluable in CC2", row.ID)
	}
}

// impactEvidence formats the credit evidence line (row id + version + via-class +
// metrics + the control proof).
func impactEvidence(row Row, version, viaClass, controlEvidence string) string {
	via := ""
	if viaClass != "" {
		via = " via " + viaClass
	}
	metrics := strings.Join(row.Credit.Metrics, ",")
	proof := controlEvidence
	if proof == "" {
		proof = "control verified"
	}
	return fmt.Sprintf("control-credit: %s v%s (%s)%s; %s High->Low", row.ID, version, proof, via, metrics)
}

// expandedCWEsLiteral returns only the row's literal CWE members (class-expanded
// members are handled separately so matchRow can attribute the class).
func (r Row) expandedCWEsLiteral() []string {
	var out []string
	for _, ref := range r.Counters.CWEClasses {
		if ref == wildcardCWE {
			continue
		}
		if !strings.HasPrefix(ref, classPrefix) {
			out = append(out, ref)
		}
	}
	return out
}

func toSet(in []string) map[string]bool {
	set := make(map[string]bool, len(in))
	for _, s := range in {
		if s = normCWE(s); s != "" {
			set[s] = true
		}
	}
	return set
}

// normCWE canonicalizes a CWE id for case-insensitive comparison.
func normCWE(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

func sortCredits(c []model.ControlCredit) {
	sort.Slice(c, func(i, j int) bool { return c[i].RowID < c[j].RowID })
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// isAvailabilityOnly reports whether a CVSS vector is availability-only
// (C:N/I:N with A:L|H, or the v4 VC/VI/VA equivalent). class:CRASH matches
// memory-safety CWEs only for such findings (classes.yaml
// membersWhenAvailabilityOnly), read here from the vector the scorer already uses.
func isAvailabilityOnly(vector string) bool {
	if strings.TrimSpace(vector) == "" {
		return false
	}
	m := map[string]string{}
	for _, tok := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(tok, ":"); ok {
			m[strings.ToUpper(strings.TrimSpace(k))] = strings.ToUpper(strings.TrimSpace(v))
		}
	}
	c, i, a := m["C"], m["I"], m["A"]
	if strings.HasPrefix(strings.ToUpper(vector), "CVSS:4") {
		c, i, a = m["VC"], m["VI"], m["VA"]
	}
	if c != "N" || i != "N" {
		return false
	}
	return a == "L" || a == "H"
}
