package controlcredit

import (
	"context"
	"reflect"
	"sort"
	"testing"
)

const fixtureDir = "testdata/taxonomy"

func TestLoadNoRefIsDisabled(t *testing.T) {
	tax, err := Load(context.Background(), "")
	if err != nil {
		t.Fatalf("Load(\"\") error = %v, want nil", err)
	}
	if tax.Enabled {
		t.Fatalf("Enabled = true, want false (no taxonomy is the default)")
	}
	if tax.Status != StatusDisabled {
		t.Fatalf("Status = %q, want %q", tax.Status, StatusDisabled)
	}
	if len(tax.Rows) != 0 {
		t.Fatalf("Rows = %d, want 0", len(tax.Rows))
	}
	if got := tax.HeaderLabel(); got != "" {
		t.Fatalf("HeaderLabel() = %q, want empty", got)
	}
}

func TestLoadLocalPathParsesRows(t *testing.T) {
	tax, err := Load(context.Background(), fixtureDir)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", fixtureDir, err)
	}
	if !tax.Enabled || tax.Status != StatusLoaded {
		t.Fatalf("Enabled=%v Status=%q, want enabled+loaded", tax.Enabled, tax.Status)
	}
	if len(tax.Rows) != 3 {
		t.Fatalf("Rows = %d, want 3", len(tax.Rows))
	}
	if tax.Tier != TierFull {
		t.Fatalf("Tier = %q, want %q", tax.Tier, TierFull)
	}
	// CHANGELOG has 0.1.0 and 0.6.0; the max wins regardless of ordering.
	if tax.Version != "0.6.0" {
		t.Fatalf("Version = %q, want 0.6.0", tax.Version)
	}
	if got := tax.HeaderLabel(); got != "full-v0.6.0" {
		t.Fatalf("HeaderLabel() = %q, want full-v0.6.0", got)
	}
	// verification sources loaded.
	if _, ok := tax.VerificationSources["no-shell-image"]; !ok {
		t.Fatalf("verification source no-shell-image missing")
	}
}

func TestClassExpansionACE(t *testing.T) {
	tax, err := Load(context.Background(), fixtureDir)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	row := rowByID(t, tax, "CC-RUN-SELINUX-CONFINE")
	got := row.CountersCWEs(false)
	want := []string{"CWE-78", "CWE-94", "CWE-502", "CWE-787"}
	assertSameSet(t, "ACE members", got, want)
	// ACE has no availability-only members, so the vector flag changes nothing.
	assertSameSet(t, "ACE members (availabilityOnly)", row.CountersCWEs(true), want)

	// Taxonomy-level expansion helper.
	assertSameSet(t, "ExpandClass(ACE)", tax.ExpandClass("ACE", false), want)
}

func TestClassExpansionCRASHVectorConditioned(t *testing.T) {
	tax, err := Load(context.Background(), fixtureDir)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	row := rowByID(t, tax, "CC-HA-RECOVERABLE-CRASH")

	// Without the availability-only vector: only unconditional CRASH members.
	assertSameSet(t, "CRASH unconditional", row.CountersCWEs(false),
		[]string{"CWE-476", "CWE-617"})

	// With an availability-only vector: unconditional plus the conditioned set.
	assertSameSet(t, "CRASH availabilityOnly", row.CountersCWEs(true),
		[]string{"CWE-476", "CWE-617", "CWE-787", "CWE-125"})

	// ExpandCRASH mirrors the per-row behavior.
	assertSameSet(t, "ExpandCRASH(false)", tax.ExpandCRASH(false),
		[]string{"CWE-476", "CWE-617"})
	assertSameSet(t, "ExpandCRASH(true)", tax.ExpandCRASH(true),
		[]string{"CWE-476", "CWE-617", "CWE-787", "CWE-125"})
}

func TestLoadRejectsUnpinnedTag(t *testing.T) {
	for _, ref := range []string{
		"stackArmor/vdr-control-credit@latest",
		"stackArmor/vdr-control-credit@main",
	} {
		tax, err := Load(context.Background(), ref)
		if err == nil {
			t.Fatalf("Load(%q) error = nil, want unpinned-tag rejection", ref)
		}
		if tax.Enabled {
			t.Fatalf("Load(%q) returned enabled taxonomy, want disabled", ref)
		}
		if tax.Status != StatusFailed {
			t.Fatalf("Load(%q) Status = %q, want %q", ref, tax.Status, StatusFailed)
		}
		if got := tax.HeaderLabel(); got != "disabled (load failed)" {
			t.Fatalf("HeaderLabel() = %q, want loud failure label", got)
		}
	}
}

func TestLoadRejectsBogusRef(t *testing.T) {
	tax, err := Load(context.Background(), "not-a-ref")
	if err == nil {
		t.Fatalf("Load error = nil, want rejection of bogus ref")
	}
	if tax.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", tax.Status, StatusFailed)
	}
}

func rowByID(t *testing.T, tax *Taxonomy, id string) Row {
	t.Helper()
	for _, r := range tax.Rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("row %q not found", id)
	return Row{}
}

func assertSameSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
}
