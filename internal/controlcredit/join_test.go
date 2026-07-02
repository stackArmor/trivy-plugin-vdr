package controlcredit

import "testing"

// impactRow builds an impact-lane row with its literal CWE counter set already
// expanded (as the loader would leave it).
func impactRow(id, control string, metrics []string, cwes ...string) Row {
	r := Row{
		ID:      id,
		Control: Control{Name: control},
		Counters: Counters{
			CWEClasses: append([]string(nil), cwes...),
		},
		Credit: Credit{Lane: laneImpact, Metrics: metrics, Move: "high-to-low"},
	}
	r.expandedCWEs = append([]string(nil), cwes...)
	return r
}

func likelihoodRow(id, control, move string, factor float64) Row {
	r := Row{
		ID:       id,
		Control:  Control{Name: control},
		Counters: Counters{CWEClasses: []string{wildcardCWE}},
		Credit:   Credit{Lane: laneLikelihood, Metrics: []string{"LEV"}, Move: move, ResidualFactor: factor},
	}
	r.expandedCWEs = []string{wildcardCWE}
	return r
}

func verified(controls ...string) map[string]VerificationResult {
	m := map[string]VerificationResult{}
	for _, c := range controls {
		m[c] = VerificationResult{Control: c, Applicable: true, Verified: true, Evidence: "verified"}
	}
	return m
}

func enabledTax(rows ...Row) *Taxonomy {
	return &Taxonomy{Enabled: true, Status: StatusLoaded, Version: "0.7.0", Rows: rows}
}

// TestJoinImpactCreditFires: a verified control keyed by the finding's CWE moves
// its Modified metrics High->Low and records a credit with the row/version.
func TestJoinImpactCreditFires(t *testing.T) {
	tax := enabledTax(impactRow("CC-NET-EGRESS-DENY", "egress-default-deny", []string{"MC", "MI"}, "CWE-94"))
	res := tax.Join(JoinInput{
		CWEs:         []string{"CWE-94"},
		EPSS:         0.10,
		Verified:     verified("egress-default-deny"),
		LEVThreshold: 0.70,
	})
	if !res.MC || !res.MI {
		t.Fatalf("MC/MI = %v/%v, want both true", res.MC, res.MI)
	}
	if res.MA {
		t.Fatalf("MA moved but the row does not touch availability")
	}
	if len(res.Credits) != 1 || res.Credits[0].RowID != "CC-NET-EGRESS-DENY" {
		t.Fatalf("credits = %+v, want one CC-NET-EGRESS-DENY", res.Credits)
	}
	if res.Credits[0].TaxonomyVersion != "0.7.0" {
		t.Fatalf("credit version = %q, want 0.7.0", res.Credits[0].TaxonomyVersion)
	}
}

// TestJoinUnverifiedControlNearMiss: a keyed row whose control is not verified
// does not fire and is recorded as a near-miss.
func TestJoinUnverifiedControlNearMiss(t *testing.T) {
	tax := enabledTax(impactRow("CC-NET-EGRESS-DENY", "egress-default-deny", []string{"MC"}, "CWE-94"))
	res := tax.Join(JoinInput{CWEs: []string{"CWE-94"}, EPSS: 0.1, Verified: map[string]VerificationResult{}, LEVThreshold: 0.7})
	if res.MC || len(res.Credits) != 0 {
		t.Fatalf("credit fired without a verified control: MC=%v credits=%+v", res.MC, res.Credits)
	}
	if len(res.NearMisses) != 1 || res.NearMisses[0].RowID != "CC-NET-EGRESS-DENY" {
		t.Fatalf("near-misses = %+v, want one CC-NET-EGRESS-DENY", res.NearMisses)
	}
}

// TestJoinNoStackingImpact: two verified rows both moving MC collapse to a single
// High->Low (MC set once) while both credits are still listed (GOVERNANCE 4a).
func TestJoinNoStackingImpact(t *testing.T) {
	tax := enabledTax(
		impactRow("CC-NET-EGRESS-DENY", "egress-default-deny", []string{"MC", "MI"}, "CWE-94"),
		impactRow("CC-NET-IMDS-PROTECT", "imds-protection", []string{"MC"}, "CWE-94"),
	)
	res := tax.Join(JoinInput{
		CWEs:         []string{"CWE-94"},
		EPSS:         0.1,
		Verified:     verified("egress-default-deny", "imds-protection"),
		LEVThreshold: 0.70,
	})
	if !res.MC {
		t.Fatalf("MC not set")
	}
	if len(res.Credits) != 2 {
		t.Fatalf("credits = %d, want 2 (both rows listed, one collapsed downgrade)", len(res.Credits))
	}
}

// TestExploitabilityMultiplicativeStacking: residual factors stack
// multiplicatively when the product stays above the STACKING_FLOOR.
func TestExploitabilityMultiplicativeStacking(t *testing.T) {
	tax := enabledTax(
		likelihoodRow("CC-LIKE-EDR-BLOCK", "blocking-runtime-protection", moveEPSSResidual, 0.85),
		likelihoodRow("CC-LIKE-EXTRA", "extra-control", moveEPSSResidual, 0.80),
	)
	res := tax.Join(JoinInput{
		CWEs:         []string{"CWE-787"},
		EPSS:         1.0,
		Verified:     verified("blocking-runtime-protection", "extra-control"),
		LEVThreshold: 0.70,
	})
	// 1.0 * 0.85 * 0.80 = 0.68, above the 0.5 floor.
	if !almost(res.Exploitability.AdjustedEPSS, 0.68) {
		t.Fatalf("adjustedEPSS = %.4f, want 0.68 (multiplicative)", res.Exploitability.AdjustedEPSS)
	}
	if res.Exploitability.EPSS != 1.0 {
		t.Fatalf("published EPSS mutated: %.4f", res.Exploitability.EPSS)
	}
}

// TestExploitabilityStackingFloor: the product is capped at EPSS * STACKING_FLOOR.
func TestExploitabilityStackingFloor(t *testing.T) {
	tax := enabledTax(
		likelihoodRow("CC-LIKE-EDR-BLOCK", "blocking-runtime-protection", moveEPSSResidual, 0.85),
		likelihoodRow("CC-LIKE-EXTRA", "extra-control", moveEPSSResidual, 0.50),
	)
	res := tax.Join(JoinInput{
		CWEs:         []string{"CWE-787"},
		EPSS:         0.90,
		Verified:     verified("blocking-runtime-protection", "extra-control"),
		LEVThreshold: 0.70,
	})
	// raw product 0.85*0.50=0.425 -> 0.90*0.425=0.3825, floored at 0.90*0.5=0.45.
	if !almost(res.Exploitability.AdjustedEPSS, 0.45) {
		t.Fatalf("adjustedEPSS = %.4f, want 0.45 (floored)", res.Exploitability.AdjustedEPSS)
	}
}

// TestExploitabilityThresholdCrossing: with a single 0.85 factor, EPSS 0.72
// crosses to NLEV while EPSS 0.99 stays LEV (spec worked example).
func TestExploitabilityThresholdCrossing(t *testing.T) {
	tax := enabledTax(likelihoodRow("CC-LIKE-EDR-BLOCK", "blocking-runtime-protection", moveEPSSResidual, 0.85))

	marginal := tax.Join(JoinInput{CWEs: []string{"CWE-787"}, EPSS: 0.72, Verified: verified("blocking-runtime-protection"), LEVThreshold: 0.70})
	if marginal.LEV {
		t.Fatalf("EPSS 0.72 * 0.85 = %.4f should be NLEV", marginal.Exploitability.AdjustedEPSS)
	}
	nearCertain := tax.Join(JoinInput{CWEs: []string{"CWE-787"}, EPSS: 0.99, Verified: verified("blocking-runtime-protection"), LEVThreshold: 0.70})
	if !nearCertain.LEV {
		t.Fatalf("EPSS 0.99 * 0.85 = %.4f should stay LEV", nearCertain.Exploitability.AdjustedEPSS)
	}
}

// TestExploitabilityKEVFrozen: a KEV finding gets no residual, adjustedEPSS ==
// EPSS, and LEV stays true regardless of a verified residual control.
func TestExploitabilityKEVFrozen(t *testing.T) {
	tax := enabledTax(likelihoodRow("CC-LIKE-EDR-BLOCK", "blocking-runtime-protection", moveEPSSResidual, 0.85))
	res := tax.Join(JoinInput{
		CWEs:         []string{"CWE-787"},
		EPSS:         0.72,
		KEV:          true,
		Verified:     verified("blocking-runtime-protection"),
		LEVThreshold: 0.70,
	})
	if !res.LEV {
		t.Fatalf("KEV finding must stay LEV")
	}
	if res.Exploitability.AdjustedEPSS != 0.72 {
		t.Fatalf("KEV adjustedEPSS = %.4f, want frozen 0.72", res.Exploitability.AdjustedEPSS)
	}
	if !res.Exploitability.KEVFrozen {
		t.Fatalf("KEVFrozen flag not set")
	}
	if len(res.Exploitability.RowIDs) != 0 {
		t.Fatalf("KEV finding applied a residual row: %v", res.Exploitability.RowIDs)
	}
}

// TestDisabledTaxonomyInert: a disabled taxonomy fires nothing and computes stock
// LEV, so the caller's no-taxonomy path is unchanged.
func TestDisabledTaxonomyInert(t *testing.T) {
	res := Disabled().Join(JoinInput{CWEs: []string{"CWE-94"}, EPSS: 0.9, LEVThreshold: 0.70})
	if res.MC || res.MI || res.MA || len(res.Credits) != 0 {
		t.Fatalf("disabled taxonomy produced credit: %+v", res)
	}
	if !res.LEV {
		t.Fatalf("stock LEV should be true at EPSS 0.9 >= 0.70")
	}
	if res.Exploitability.AdjustedEPSS != 0.9 {
		t.Fatalf("adjustedEPSS = %.4f, want unchanged 0.9", res.Exploitability.AdjustedEPSS)
	}
}

func almost(got, want float64) bool {
	d := got - want
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}
