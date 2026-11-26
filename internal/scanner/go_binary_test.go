package scanner

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGoBinaryFilterRequiresMatchingAdvisoryAndEvidence(t *testing.T) {
	const stream = `
{"config":{"protocol_version":"v1.0.0","scan_mode":"binary","scan_level":"symbol"}}
{"SBOM":{"modules":[{"path":"stdlib","version":"go1.24.0"}]}}
{"osv":{"id":"GO-test-absent","aliases":["CVE-test-absent"],"affected":[{"package":{"name":"stdlib"},"ecosystem_specific":{"imports":[{"path":"net/http"}]}}]}}
{"finding":{"osv":"GO-test-absent","trace":[{"module":"stdlib","version":"v1.24.0"}]}}
{"finding":{"osv":"GO-test-absent","trace":[{"module":"stdlib","version":"v1.24.0","package":"net/http"}]}}
{"osv":{"id":"GO-test-present","affected":[{"package":{"name":"stdlib"},"ecosystem_specific":{"imports":[{"path":"net/http"}]}}]}}
{"finding":{"osv":"GO-test-present","trace":[{"module":"stdlib","version":"v1.24.0","package":"net/http","function":"Serve"}]}}
{"finding":{"osv":"GO-test-present","trace":[{"module":"stdlib","version":"v1.24.0"}]}}
{"osv":{"id":"GO-test-platform","affected":[{"package":{"name":"stdlib"},"ecosystem_specific":{"imports":[{"path":"os","goos":["windows"]}]}}]}}
{"osv":{"id":"GO-test-broad","affected":[{"package":{"name":"stdlib"}}]}}
{"finding":{"osv":"GO-test-broad","trace":[{"module":"stdlib","version":"v1.24.0"}]}}
{"osv":{"id":"GO-test-unconfirmed","affected":[{"package":{"name":"stdlib"},"ecosystem_specific":{"imports":[{"path":"net/http"}]}}]}}
{"osv":{"id":"GO-test-overlap","aliases":["CVE-test-absent"],"affected":[{"package":{"name":"example.com/module"},"ecosystem_specific":{"imports":[{"path":"example.com/module"}]}}]}}
`
	for _, tc := range []struct {
		name, id, version, os string
		omit                  bool
	}{
		{"matched module and no vulnerable symbols", "CVE-test-absent", "v1.24.0", "linux", true},
		{"vulnerable symbol present", "GO-test-present", "v1.24.0", "linux", false},
		{"build platform excluded", "GO-test-platform", "v1.24.0", "linux", true},
		{"build platform affected", "GO-test-platform", "v1.24.0", "windows", false},
		{"build platform unknown", "GO-test-platform", "v1.24.0", "", false},
		{"no package information", "GO-test-broad", "v1.24.0", "linux", false},
		{"no matching module finding", "GO-test-unconfirmed", "v1.24.0", "linux", false},
		{"different module version", "CVE-test-absent", "v1.24.1", "linux", false},
		{"unrecognized advisory", "CVE-test-unknown", "v1.24.0", "linux", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence, err := readGoBinaryEvidence(strings.NewReader(stream), tc.os, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			vuln := trivyVulnerability{VulnerabilityID: tc.id, PkgName: "stdlib", InstalledVersion: tc.version}
			if got := evidence.canOmit(vuln); got != tc.omit {
				t.Errorf("canOmit(%s) = %t, want %t", tc.id, got, tc.omit)
			}
		})
	}
}

func TestGoBinaryFilterRejectsIncompleteOrUnsupportedGovulncheckOutput(t *testing.T) {
	for _, input := range []string{
		`{"config":{"protocol_version":"v1.0.0","scan_mode":"binary","scan_level":"symbol"}}`,
		`{"config":{"protocol_version":"v1.0.0","scan_mode":"source","scan_level":"symbol"}}`,
		`{"config":{"protocol_version":"v1.0.0","scan_mode":"binary","scan_level":"symbol"}} {`,
	} {
		if _, err := readGoBinaryEvidence(strings.NewReader(input), "linux", "amd64"); err == nil {
			t.Errorf("accepted invalid govulncheck stream %q", input)
		}
	}
}

func TestGoTemporaryBudgetSharedBetweenWorkers(t *testing.T) {
	f := NewGoBinaryFilter(0, 0)
	f.reserved = goBinaryTempLimit - 8
	if err := f.reserve(t.TempDir(), 9); !errors.Is(err, errTempSpace) {
		t.Fatalf("reservation beyond remaining budget: %v", err)
	}
	f.release(f.reserved)
	if err := f.reserve(t.TempDir(), 9); err != nil {
		t.Fatal(err)
	}
	if f.peak != 9 {
		t.Fatalf("peak = %d", f.peak)
	}
}

func TestFailedBinaryCheckReclaimsTemporarySpace(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	f := NewGoBinaryFilter(0, 0)
	for _, size := range []int64{3, 10} {
		if _, err := f.scanEntry(context.Background(), "", strings.NewReader("bad"), size); err == nil {
			t.Fatal("expected invalid or truncated binary to fail")
		}
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 0 || f.reserved != 0 {
			t.Fatalf("after failed check: files=%v reserved=%d err=%v", files, f.reserved, err)
		}
	}
}

func TestGoFilterRetainsFindingsWhenBothSlotsBusyAtDeadline(t *testing.T) {
	filter := NewGoBinaryFilter(0, 0)
	filter.slots <- struct{}{}
	filter.slots <- struct{}{}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	v := trivyVulnerability{VulnerabilityID: "CVE-test"}
	v.Layer.Digest = "sha256:test"
	report := trivyReport{Results: []trivyResult{{Type: "gobinary", Target: "app", Vulnerabilities: []trivyVulnerability{v}}}}
	runner := TrivyRunner{GoBinaryFilter: filter}
	runner.filterGoBinaryFindings(ctx, "example", &report)
	if len(report.Results[0].Vulnerabilities) != 1 || filter.skips["deadline_or_cancel"] != 1 {
		t.Fatalf("findings=%v skips=%v", report.Results[0].Vulnerabilities, filter.skips)
	}
}
