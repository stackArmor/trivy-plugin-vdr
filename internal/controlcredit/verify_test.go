package controlcredit

import (
	"context"
	"testing"
)

// TestVerifyReadOnlyRootFS: the readonly-rootfs k8s collector verifies only when
// every container is read-only and no writable app volume is mounted.
func TestVerifyReadOnlyRootFS(t *testing.T) {
	tax := &Taxonomy{
		Enabled: true, Status: StatusLoaded,
		Rows: []Row{{ID: "CC-RUN-ROFS", Control: Control{Name: "readonly-rootfs"}, Credit: Credit{Lane: laneImpact}}},
		VerificationSources: map[string]VerificationSource{
			"readonly-rootfs": {PlatformKubernetes: "securityContext.readOnlyRootFilesystem=true on every container"},
		},
	}

	ok := tax.VerifyControls(AssetFacts{Platform: PlatformKubernetes, ReadOnlyRootFS: true})
	if !ok["readonly-rootfs"].Verified {
		t.Fatalf("readonly-rootfs should verify when all containers are read-only")
	}

	bad := tax.VerifyControls(AssetFacts{Platform: PlatformKubernetes, ReadOnlyRootFS: true, WritableAppVolume: true})
	if bad["readonly-rootfs"].Verified {
		t.Fatalf("readonly-rootfs must not verify with a writable app volume mounted")
	}
	if bad["readonly-rootfs"].FailedPredicate == "" {
		t.Fatalf("expected a failed-predicate for near-miss reporting")
	}
}

// TestVerifyInapplicableControl: a control with no predicate for the platform is
// cleanly not-verified (no k8s signal => STIG/cloud controls fire nowhere here).
func TestVerifyInapplicableControl(t *testing.T) {
	tax := &Taxonomy{
		Enabled: true, Status: StatusLoaded,
		Rows: []Row{{ID: "CC-DATA-DB-TLS", Control: Control{Name: "db-tls-required"}, Credit: Credit{Lane: laneImpact}}},
		VerificationSources: map[string]VerificationSource{
			"db-tls-required": {"aws-managed": "rds.force_ssl=1"},
		},
	}
	res := tax.VerifyControls(AssetFacts{Platform: PlatformKubernetes})
	if res["db-tls-required"].Verified || res["db-tls-required"].Applicable {
		t.Fatalf("db-tls-required has no kubernetes predicate; must be inapplicable, got %+v", res["db-tls-required"])
	}
}

// TestVerifyUncollectedControl: a control with a k8s predicate whose collector is
// not implemented in CC2 is not verified and flags the gap (not assumed present).
func TestVerifyUncollectedControl(t *testing.T) {
	tax := &Taxonomy{
		Enabled: true, Status: StatusLoaded,
		Rows: []Row{{ID: "CC-WEB-CSP", Control: Control{Name: "strict-csp"}, Credit: Credit{Lane: laneImpact}}},
		VerificationSources: map[string]VerificationSource{
			"strict-csp": {PlatformKubernetes: "CSP enforced at the edge on tainted routes"},
		},
	}
	res := tax.VerifyControls(AssetFacts{Platform: PlatformKubernetes})
	got := res["strict-csp"]
	if got.Verified {
		t.Fatalf("strict-csp collector is not implemented; must not verify")
	}
	if got.FailedPredicate == "" {
		t.Fatalf("uncollected control should record a TODO failed-predicate")
	}
}

// TestJoinCRASHAvailabilityOnly exercises the loader's class expansion end to end:
// a class:CRASH row keyed via a memory-safety CWE fires only when the finding's
// vector is availability-only, and the credit records the class it matched through.
func TestJoinCRASHAvailabilityOnly(t *testing.T) {
	tax, err := Load(context.Background(), fixtureDir)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", fixtureDir, err)
	}
	// Point the fixture's verified-ha predicate at kubernetes so verification and
	// the join can be exercised, and mark it verified with the rate-limit
	// conjunction (route-rate-limit) so the IRV-conservative HA condition passes.
	v := verified("verified-ha", "route-rate-limit")

	// CWE-787 is a CRASH member only when availability-only.
	availOnly := tax.Join(JoinInput{
		CWEs:         []string{"CWE-787"},
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		Verified:     v,
		LEVThreshold: 0.70,
	})
	if !availOnly.MA {
		t.Fatalf("CC-HA-RECOVERABLE-CRASH should fire for CWE-787 on an availability-only vector")
	}
	if len(availOnly.Credits) != 1 || availOnly.Credits[0].ViaClass != "class:CRASH" {
		t.Fatalf("credit viaClass = %+v, want class:CRASH", availOnly.Credits)
	}

	// Same CWE with a confidentiality/integrity vector is NOT a CRASH member.
	notAvail := tax.Join(JoinInput{
		CWEs:         []string{"CWE-787"},
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Verified:     v,
		LEVThreshold: 0.70,
	})
	if notAvail.MA {
		t.Fatalf("CWE-787 with a C:H/I:H vector must not match class:CRASH")
	}
}

// TestJoinHAConservativeIRV: without route-rate-limit verified, the HA crash row
// is blocked under the v1 IRV-conservative reachability fallback (handoff).
func TestJoinHAConservativeIRV(t *testing.T) {
	tax, err := Load(context.Background(), fixtureDir)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	res := tax.Join(JoinInput{
		CWEs:         []string{"CWE-476"}, // unconditional CRASH member
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		Verified:     verified("verified-ha"), // no route-rate-limit
		LEVThreshold: 0.70,
	})
	if res.MA {
		t.Fatalf("HA crash credit should be blocked without verified route-rate-limit (IRV-conservative)")
	}
	if len(res.NearMisses) == 0 {
		t.Fatalf("expected a near-miss recording the rate-limit gap")
	}
}
