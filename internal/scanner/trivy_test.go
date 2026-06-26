package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

func TestTrivyRunnerBuildsImageScanCommand(t *testing.T) {
	fake := &fakeCommandRunner{
		stdout: []byte(`{"Results":[]}`),
	}
	runner := TrivyRunner{
		Binary:        "trivy-test",
		CommandRunner: fake,
	}

	_, err := runner.ScanImage(context.Background(), "registry.example.com/app:v1", 45*time.Second)
	if err != nil {
		t.Fatalf("ScanImage returned error: %v", err)
	}

	if fake.name != "trivy-test" {
		t.Fatalf("command name = %q, want trivy-test", fake.name)
	}
	wantArgs := []string{"image", "--image-src", "remote", "--skip-version-check", "--format", "json", "--scanners", "vuln", "--timeout", "45s", "registry.example.com/app:v1"}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", fake.args, wantArgs)
	}
}

func TestTrivyRunnerBuildsImageScanCommandWithCustomImageSource(t *testing.T) {
	fake := &fakeCommandRunner{
		stdout: []byte(`{"Results":[]}`),
	}
	runner := TrivyRunner{
		Binary:        "trivy-test",
		ImageSrc:      "remote,local",
		CommandRunner: fake,
	}

	_, err := runner.ScanImage(context.Background(), "registry.example.com/app:v1", 45*time.Second)
	if err != nil {
		t.Fatalf("ScanImage returned error: %v", err)
	}

	wantArgs := []string{"image", "--image-src", "remote,local", "--skip-version-check", "--format", "json", "--scanners", "vuln", "--timeout", "45s", "registry.example.com/app:v1"}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", fake.args, wantArgs)
	}
}

func TestTrivyRunnerBuildsImageScanCommandWithCacheDir(t *testing.T) {
	fake := &fakeCommandRunner{
		stdout: []byte(`{"Results":[]}`),
	}
	runner := TrivyRunner{
		Binary:        "trivy-test",
		CacheDir:      "/tmp/trivy-cache",
		CommandRunner: fake,
	}

	_, err := runner.ScanImage(context.Background(), "registry.example.com/app:v1", 45*time.Second)
	if err != nil {
		t.Fatalf("ScanImage returned error: %v", err)
	}

	wantArgs := []string{"image", "--cache-dir", "/tmp/trivy-cache", "--image-src", "remote", "--skip-version-check", "--format", "json", "--scanners", "vuln", "--timeout", "45s", "registry.example.com/app:v1"}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", fake.args, wantArgs)
	}
}

func TestTrivyRunnerParsesVulnerabilitiesFromMultipleResults(t *testing.T) {
	runner := TrivyRunner{
		Binary: "trivy",
		CommandRunner: &fakeCommandRunner{
			stdout: []byte(`{
				"Results": [
					{
						"Target": "libssl",
						"Vulnerabilities": [
							{
								"VulnerabilityID": "CVE-2026-0001",
								"PkgName": "openssl",
								"InstalledVersion": "1.1.1",
								"FixedVersion": "1.1.2",
								"Severity": "HIGH",
								"Title": "openssl issue",
								"Description": "bad openssl",
								"References": ["https://example.com/cve"],
								"Status": "fixed",
								"CVSS": {
									"redhat": { "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L" },
									"nvd": { "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
								}
							}
						]
					},
					{
						"Target": "busybox",
						"Vulnerabilities": [
							{
								"VulnerabilityID": "CVE-2026-0002",
								"PkgName": "busybox",
								"InstalledVersion": "1.36.0",
								"Severity": "MEDIUM"
							}
						]
					}
				]
			}`),
		},
	}

	findings, err := runner.ScanImage(context.Background(), "registry.example.com/app:v1", time.Minute)
	if err != nil {
		t.Fatalf("ScanImage returned error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %#v", len(findings), findings)
	}
	first := findings[0]
	if first.ID != "CVE-2026-0001" ||
		first.ImageRef != "registry.example.com/app:v1" ||
		first.PackageName != "openssl" ||
		first.InstalledVersion != "1.1.1" ||
		first.FixedVersion != "1.1.2" ||
		first.Severity != "HIGH" ||
		first.Title != "openssl issue" ||
		first.Description != "bad openssl" ||
		first.Status != "fixed" {
		t.Fatalf("first finding did not preserve fields: %#v", first)
	}
	if first.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("CVSSVector = %q, want NVD v3 vector preferred over redhat", first.CVSSVector)
	}
	if !reflect.DeepEqual(first.References, []string{"https://example.com/cve"}) {
		t.Fatalf("References = %#v", first.References)
	}

	second := findings[1]
	if second.ID != "CVE-2026-0002" || second.PackageName != "busybox" || second.ImageRef != "registry.example.com/app:v1" {
		t.Fatalf("second finding did not parse from second result: %#v", second)
	}
}

func TestTrivyRunnerEmptyOrMissingVulnerabilitiesReturnsNoFindings(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{name: "empty results", json: `{"Results":[]}`},
		{name: "missing vulnerabilities", json: `{"Results":[{"Target":"alpine"}]}`},
		{name: "empty vulnerabilities", json: `{"Results":[{"Target":"alpine","Vulnerabilities":[]}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := TrivyRunner{CommandRunner: &fakeCommandRunner{stdout: []byte(tt.json)}}

			findings, err := runner.ScanImage(context.Background(), "alpine:3.20", time.Second)
			if err != nil {
				t.Fatalf("ScanImage returned error: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("len(findings) = %d, want 0: %#v", len(findings), findings)
			}
		})
	}
}

func TestTrivyRunnerIncludesStderrOnCommandFailure(t *testing.T) {
	runner := TrivyRunner{
		CommandRunner: &fakeCommandRunner{
			stderr: []byte("unable to pull image"),
			err:    errors.New("exit status 1"),
		},
	}

	_, err := runner.ScanImage(context.Background(), "missing:image", time.Second)
	if err == nil {
		t.Fatal("ScanImage returned nil error")
	}
	if !strings.Contains(err.Error(), "trivy image scan failed") ||
		!strings.Contains(err.Error(), "missing:image") ||
		!strings.Contains(err.Error(), "unable to pull image") {
		t.Fatalf("error = %q, want useful command failure with stderr", err.Error())
	}
}

func TestTrivyRunnerInvalidJSONReturnsUsefulError(t *testing.T) {
	runner := TrivyRunner{CommandRunner: &fakeCommandRunner{stdout: []byte(`not-json`)}}

	_, err := runner.ScanImage(context.Background(), "alpine:3.20", time.Second)
	if err == nil {
		t.Fatal("ScanImage returned nil error")
	}
	if !strings.Contains(err.Error(), "parse trivy JSON") {
		t.Fatalf("error = %q, want parse context", err.Error())
	}
}

func TestScanInventoryScansUniqueImagesAndFansOutAffectedResources(t *testing.T) {
	webRef := model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "web", ContainerName: "app", ContainerType: "container"}
	jobRef := model.ResourceRef{APIVersion: "batch/v1", Kind: "Job", Namespace: "default", Name: "migrate", ContainerName: "app", ContainerType: "container"}
	apiRef := model.ResourceRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "prod", Name: "api", ContainerName: "api", ContainerType: "container"}
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/web:v1", NormalizedImage: "registry.example.com/web", Resources: []model.ResourceRef{webRef}},
			{ImageRef: "registry.example.com/web:v1", NormalizedImage: "registry.example.com/web", Resources: []model.ResourceRef{jobRef}},
			{ImageRef: "registry.example.com/api:v2", NormalizedImage: "registry.example.com/api", Resources: []model.ResourceRef{apiRef}},
		},
	}
	runner := &fakeImageRunner{
		findings: map[string][]model.Finding{
			"registry.example.com/web:v1": {{ID: "CVE-2026-0001", PackageName: "openssl", Severity: "HIGH"}},
			"registry.example.com/api:v2": {{ID: "CVE-2026-0002", PackageName: "busybox", Severity: "LOW"}},
		},
	}

	findings, err := ScanInventory(context.Background(), inventory, runner, 30*time.Second)
	if err != nil {
		t.Fatalf("ScanInventory returned error: %v", err)
	}

	if !reflect.DeepEqual(runner.images, []string{"registry.example.com/web:v1", "registry.example.com/api:v2"}) {
		t.Fatalf("scanned images = %#v, want each unique image once in inventory order", runner.images)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %#v", len(findings), findings)
	}

	webFinding := findings[0]
	if webFinding.ImageRef != "registry.example.com/web:v1" {
		t.Fatalf("web ImageRef = %q", webFinding.ImageRef)
	}
	if webFinding.NormalizedImage != "registry.example.com/web" {
		t.Fatalf("web NormalizedImage = %q", webFinding.NormalizedImage)
	}
	if !reflect.DeepEqual(webFinding.AffectedResources, []model.ResourceRef{webRef, jobRef}) {
		t.Fatalf("web affected resources = %#v", webFinding.AffectedResources)
	}

	apiFinding := findings[1]
	if apiFinding.ImageRef != "registry.example.com/api:v2" {
		t.Fatalf("api ImageRef = %q", apiFinding.ImageRef)
	}
	if apiFinding.NormalizedImage != "registry.example.com/api" {
		t.Fatalf("api NormalizedImage = %q", apiFinding.NormalizedImage)
	}
	if !reflect.DeepEqual(apiFinding.AffectedResources, []model.ResourceRef{apiRef}) {
		t.Fatalf("api affected resources = %#v", apiFinding.AffectedResources)
	}
}

func TestScanInventoryWithOptionsScansConcurrentlyAndReturnsFindingsByImageRef(t *testing.T) {
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/z:v1", Resources: []model.ResourceRef{{Kind: "Deployment", Name: "z"}}},
			{ImageRef: "registry.example.com/a:v1", Resources: []model.ResourceRef{{Kind: "Deployment", Name: "a"}}},
			{ImageRef: "registry.example.com/m:v1", Resources: []model.ResourceRef{{Kind: "Deployment", Name: "m"}}},
		},
	}
	runner := newBlockingImageRunner(map[string][]model.Finding{
		"registry.example.com/z:v1": {{ID: "CVE-Z"}},
		"registry.example.com/a:v1": {{ID: "CVE-A"}},
		"registry.example.com/m:v1": {{ID: "CVE-M"}},
	})

	resultCh := make(chan struct {
		findings []model.Finding
		warnings []Warning
		err      error
	}, 1)
	go func() {
		findings, warnings, err := ScanInventoryWithOptions(context.Background(), inventory, runner, ScanOptions{
			Timeout:       30 * time.Second,
			ParallelScans: 2,
			CacheCleanup:  CleanupNever,
		})
		resultCh <- struct {
			findings []model.Finding
			warnings []Warning
			err      error
		}{findings: findings, warnings: warnings, err: err}
	}()

	runner.waitUntilActive(t, 2)
	if got := runner.maxActive(); got > 2 {
		t.Fatalf("max active scans = %d, want at most 2", got)
	}
	runner.release("registry.example.com/z:v1")
	runner.waitUntilStarted(t, "registry.example.com/m:v1")
	runner.release("registry.example.com/m:v1")
	runner.release("registry.example.com/a:v1")

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("ScanInventoryWithOptions returned error: %v", result.err)
	}
	if len(result.warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", result.warnings)
	}
	var gotIDs []string
	for _, finding := range result.findings {
		gotIDs = append(gotIDs, finding.ID)
	}
	wantIDs := []string{"CVE-A", "CVE-M", "CVE-Z"}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("finding IDs = %#v, want sorted by image ref %#v", gotIDs, wantIDs)
	}
}

func TestScanInventoryWithOptionsDefaultsToFiveParallelScans(t *testing.T) {
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/a:v1"},
			{ImageRef: "registry.example.com/b:v1"},
			{ImageRef: "registry.example.com/c:v1"},
			{ImageRef: "registry.example.com/d:v1"},
			{ImageRef: "registry.example.com/e:v1"},
			{ImageRef: "registry.example.com/f:v1"},
		},
	}
	runner := newBlockingImageRunner(map[string][]model.Finding{
		"registry.example.com/a:v1": {{ID: "CVE-A"}},
		"registry.example.com/b:v1": {{ID: "CVE-B"}},
		"registry.example.com/c:v1": {{ID: "CVE-C"}},
		"registry.example.com/d:v1": {{ID: "CVE-D"}},
		"registry.example.com/e:v1": {{ID: "CVE-E"}},
		"registry.example.com/f:v1": {{ID: "CVE-F"}},
	})

	resultCh := make(chan error, 1)
	go func() {
		_, _, err := ScanInventoryWithOptions(context.Background(), inventory, runner, ScanOptions{
			CacheCleanup: CleanupNever,
		})
		resultCh <- err
	}()

	runner.waitUntilActive(t, 5)
	if got := runner.maxActive(); got > 5 {
		t.Fatalf("max active scans = %d, want at most 5", got)
	}
	runner.release("registry.example.com/a:v1")
	runner.waitUntilStarted(t, "registry.example.com/f:v1")
	for _, image := range []string{
		"registry.example.com/b:v1",
		"registry.example.com/c:v1",
		"registry.example.com/d:v1",
		"registry.example.com/e:v1",
		"registry.example.com/f:v1",
	} {
		runner.release(image)
	}

	if err := <-resultCh; err != nil {
		t.Fatalf("ScanInventoryWithOptions returned error: %v", err)
	}
	if got := runner.maxActive(); got != 5 {
		t.Fatalf("max active scans = %d, want default parallelism 5", got)
	}
}

func TestScanInventoryWithOptionsSurfacesCleanupWarningWithoutDroppingFindings(t *testing.T) {
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/app:v1", Resources: []model.ResourceRef{{Kind: "Deployment", Name: "app"}}},
		},
	}
	runner := &fakeImageRunner{
		findings: map[string][]model.Finding{
			"registry.example.com/app:v1": {{ID: "CVE-2026-0001"}},
		},
	}
	cleaner := &fakeCacheCleaner{err: errors.New("clean failed")}

	findings, warnings, err := ScanInventoryWithOptions(context.Background(), inventory, runner, ScanOptions{
		Timeout:       time.Minute,
		ParallelScans: 1,
		CacheCleanup:  CleanupAlways,
		CacheCleaner:  cleaner,
	})
	if err != nil {
		t.Fatalf("ScanInventoryWithOptions returned error: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "CVE-2026-0001" {
		t.Fatalf("findings = %#v, want scan result preserved", findings)
	}
	if got := cleaner.callCount(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v, want one cleanup warning", warnings)
	}
	if warnings[0].ImageRef != "" || !strings.Contains(warnings[0].Message, "clean failed") {
		t.Fatalf("warning = %#v, want global cleanup failure context", warnings[0])
	}
}

func TestScanInventoryWithOptionsRunsCleanupAfterAllScansComplete(t *testing.T) {
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/a:v1"},
			{ImageRef: "registry.example.com/b:v1"},
		},
	}
	runner := newBlockingImageRunner(map[string][]model.Finding{
		"registry.example.com/a:v1": {{ID: "CVE-A"}},
		"registry.example.com/b:v1": {{ID: "CVE-B"}},
	})
	cleaner := &activeCheckingCacheCleaner{active: runner.activeCount}

	resultCh := make(chan error, 1)
	go func() {
		_, _, err := ScanInventoryWithOptions(context.Background(), inventory, runner, ScanOptions{
			Timeout:       time.Minute,
			ParallelScans: 2,
			CacheCleanup:  CleanupAlways,
			CacheCleaner:  cleaner,
		})
		resultCh <- err
	}()

	runner.waitUntilActive(t, 2)
	if got := cleaner.callCount(); got != 0 {
		t.Fatalf("cleanup calls while scans active = %d, want 0", got)
	}
	runner.release("registry.example.com/a:v1")
	runner.release("registry.example.com/b:v1")

	if err := <-resultCh; err != nil {
		t.Fatalf("ScanInventoryWithOptions returned error: %v", err)
	}
	if got := cleaner.callCount(); got != 1 {
		t.Fatalf("cleanup calls = %d, want one post-scan cleanup", got)
	}
	if cleaner.didOverlap() {
		t.Fatal("cleanup ran while image scans were active")
	}
}

func TestEnsureDatabasesDownloadsVulnAndJavaDB(t *testing.T) {
	fake := &fakeCommandRunner{stdout: []byte("")}
	runner := TrivyRunner{Binary: "trivy-test", CacheDir: "/tmp/trivy-cache", CommandRunner: fake}
	if err := runner.EnsureDatabases(context.Background()); err != nil {
		t.Fatalf("EnsureDatabases error: %v", err)
	}
	want := [][]string{
		{"image", "--download-db-only", "--skip-version-check", "--cache-dir", "/tmp/trivy-cache"},
		{"image", "--download-java-db-only", "--skip-version-check", "--cache-dir", "/tmp/trivy-cache"},
	}
	if !reflect.DeepEqual(fake.callArgs, want) {
		t.Fatalf("calls = %#v, want %#v", fake.callArgs, want)
	}
}

func TestScanImageSkipDBUpdateAddsFlags(t *testing.T) {
	fake := &fakeCommandRunner{stdout: []byte(`{"Results":[]}`)}
	runner := TrivyRunner{Binary: "trivy-test", CacheDir: "/tmp/trivy-cache", SkipDBUpdate: true, CommandRunner: fake}

	if _, err := runner.ScanImage(context.Background(), "registry.example.com/app:v1", 45*time.Second); err != nil {
		t.Fatalf("ScanImage error: %v", err)
	}
	wantArgs := []string{"image", "--cache-dir", "/tmp/trivy-cache", "--skip-db-update", "--skip-java-db-update", "--image-src", "remote", "--skip-version-check", "--format", "json", "--scanners", "vuln", "--timeout", "45s", "registry.example.com/app:v1"}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", fake.args, wantArgs)
	}
}

func TestPrepareWorkerCachesHardlinksDatabases(t *testing.T) {
	base := t.TempDir()
	for _, sub := range []string{"db", "java-db"} {
		dir := filepath.Join(base, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "data.db"), []byte("payload"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", sub, err)
		}
	}

	runner := TrivyRunner{Binary: "trivy-test", CacheDir: base, CommandRunner: &fakeCommandRunner{}}
	prepared, cleanup, err := runner.PrepareWorkerCaches(3)
	if err != nil {
		t.Fatalf("PrepareWorkerCaches error: %v", err)
	}
	if prepared.workerCaches == nil || len(prepared.workerCaches.dirs) != 3 {
		t.Fatalf("expected 3 worker caches, got %#v", prepared.workerCaches)
	}

	srcInfo, _ := os.Stat(filepath.Join(base, "db", "data.db"))
	for _, dir := range prepared.workerCaches.dirs {
		linked := filepath.Join(dir, "db", "data.db")
		info, statErr := os.Stat(linked)
		if statErr != nil {
			t.Fatalf("worker db missing: %v", statErr)
		}
		if !os.SameFile(srcInfo, info) {
			t.Fatalf("worker db is not a hardlink of the base db")
		}
	}

	cleanup()
	for _, dir := range prepared.workerCaches.dirs {
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Fatalf("worker cache %s not removed after cleanup", dir)
		}
	}
}

func TestPrepareWorkerCachesNoopForSerial(t *testing.T) {
	runner := TrivyRunner{Binary: "trivy-test", CacheDir: t.TempDir(), CommandRunner: &fakeCommandRunner{}}
	prepared, cleanup, err := runner.PrepareWorkerCaches(1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	defer cleanup()
	if prepared.workerCaches != nil {
		t.Fatalf("expected no worker caches for n=1")
	}
}

func TestScanImageSelfHealRetriesOnCorruption(t *testing.T) {
	fake := &healingFakeRunner{
		failScans:  1,
		scanErr:    errors.New("exit status 2: panic: unexpected fault address"),
		scanStdout: []byte(`{"Results":[]}`),
	}
	runner := TrivyRunner{Binary: "trivy-test", CacheDir: "/tmp/trivy-cache", SkipDBUpdate: true, CommandRunner: fake}.WithSelfHeal()

	if _, err := runner.ScanImage(context.Background(), "registry.example.com/app:v1", time.Minute); err != nil {
		t.Fatalf("ScanImage error after heal: %v", err)
	}
	if fake.downloads == 0 {
		t.Fatalf("expected a re-download during heal, got none")
	}
	if fake.scans < 2 {
		t.Fatalf("expected a retry scan, got %d scans", fake.scans)
	}
}

// healingFakeRunner fails the first N scans, then succeeds, and counts DB downloads.
type healingFakeRunner struct {
	failScans  int
	scans      int
	downloads  int
	scanErr    error
	scanStdout []byte
}

func (f *healingFakeRunner) Run(_ context.Context, _ string, args ...string) ([]byte, []byte, error) {
	for _, a := range args {
		if a == "--download-db-only" || a == "--download-java-db-only" {
			f.downloads++
			return nil, nil, nil
		}
	}
	f.scans++
	if f.scans <= f.failScans {
		return nil, []byte("panic: unexpected fault address"), f.scanErr
	}
	return f.scanStdout, nil, nil
}

func TestTrivyRunnerDockerEnv(t *testing.T) {
	if env := (TrivyRunner{}).dockerEnv(); env != nil {
		t.Fatalf("dockerEnv() = %v, want nil when no dir set", env)
	}
	env := (TrivyRunner{DockerConfigDir: "/tmp/x"}).dockerEnv()
	if len(env) != 1 || env[0] != "DOCKER_CONFIG=/tmp/x" {
		t.Fatalf("dockerEnv() = %v, want [DOCKER_CONFIG=/tmp/x]", env)
	}
}

func TestExecCommandRunnerPropagatesExtraEnv(t *testing.T) {
	runner := execCommandRunner{extraEnv: []string{"DOCKER_CONFIG=/tmp/vdr-test-cfg"}}
	stdout, _, err := runner.Run(context.Background(), "sh", "-c", `printf %s "$DOCKER_CONFIG"`)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := string(stdout); got != "/tmp/vdr-test-cfg" {
		t.Fatalf("DOCKER_CONFIG = %q, want /tmp/vdr-test-cfg", got)
	}
}

func TestScanInventoryWithOptionsConvertsImageErrorToWarningAndContinues(t *testing.T) {
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/a:v1"},
			{ImageRef: "registry.example.com/z:v1"},
		},
	}
	runner := &errImageRunner{
		findings: map[string][]model.Finding{
			"registry.example.com/a:v1": {{ID: "CVE-A"}},
		},
		errs: map[string]error{
			"registry.example.com/z:v1": errors.New("signal: killed"),
		},
	}

	findings, warnings, err := ScanInventoryWithOptions(context.Background(), inventory, runner, ScanOptions{
		Timeout:       time.Minute,
		ParallelScans: 2,
		CacheCleanup:  CleanupNever,
	})
	if err != nil {
		t.Fatalf("error = %v, want nil (failures become warnings)", err)
	}
	if len(findings) != 1 || findings[0].ID != "CVE-A" {
		t.Fatalf("findings = %#v, want the successful image's findings", findings)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v, want 1 per-image warning", warnings)
	}
	if warnings[0].ImageRef != "registry.example.com/z:v1" || !strings.Contains(warnings[0].Message, "signal: killed") {
		t.Fatalf("warning = %#v, want failing image ref and message", warnings[0])
	}
}

func TestScanInventoryWithOptionsReturnsParentCancellationDuringCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/app:v1", Resources: []model.ResourceRef{{Kind: "Deployment", Name: "app"}}},
		},
	}
	runner := &fakeImageRunner{
		findings: map[string][]model.Finding{
			"registry.example.com/app:v1": {{ID: "CVE-2026-0001"}},
		},
	}
	cleaner := &cancelingCacheCleaner{cancel: cancel}

	findings, warnings, err := ScanInventoryWithOptions(ctx, inventory, runner, ScanOptions{
		Timeout:       time.Minute,
		ParallelScans: 1,
		CacheCleanup:  CleanupAlways,
		CacheCleaner:  cleaner,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want nil on cleanup cancellation error", findings)
	}
	if warnings != nil {
		t.Fatalf("warnings = %#v, want nil on cleanup cancellation error", warnings)
	}
}

func TestScanInventoryWithOptionsReturnsParentCancellationOverProcessKillError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	processErr := errors.New("signal: killed")
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/app:v1"},
		},
	}
	runner := &parentCancelingImageRunner{
		cancel: cancel,
		err:    processErr,
	}

	_, _, err := ScanInventoryWithOptions(ctx, inventory, runner, ScanOptions{
		Timeout:       time.Minute,
		ParallelScans: 1,
		CacheCleanup:  CleanupNever,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if errors.Is(err, processErr) {
		t.Fatalf("error = %v, want parent cancellation to take precedence over process kill error", err)
	}
}

func TestScanInventoryWithOptionsReturnsContextErrorWhenCanceledBeforeScheduling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inventory := &model.Inventory{
		Images: []model.ImageInventory{
			{ImageRef: "registry.example.com/app:v1"},
		},
	}

	_, _, err := ScanInventoryWithOptions(ctx, inventory, &fakeImageRunner{}, ScanOptions{
		Timeout:       time.Minute,
		ParallelScans: 1,
		CacheCleanup:  CleanupNever,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

type fakeCommandRunner struct {
	name     string
	args     []string
	callArgs [][]string
	stdout   []byte
	stderr   []byte
	err      error
}

func (f *fakeCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.name = name
	f.args = append([]string(nil), args...)
	f.callArgs = append(f.callArgs, append([]string(nil), args...))
	return f.stdout, f.stderr, f.err
}

type fakeImageRunner struct {
	images   []string
	findings map[string][]model.Finding
}

func (f *fakeImageRunner) ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error) {
	f.images = append(f.images, image)
	return f.findings[image], nil
}

type fakeCacheCleaner struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeCacheCleaner) Cleanup(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeCacheCleaner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type cancelingCacheCleaner struct {
	cancel context.CancelFunc
}

func (f *cancelingCacheCleaner) Cleanup(ctx context.Context) error {
	f.cancel()
	return ctx.Err()
}

type activeCheckingCacheCleaner struct {
	mu         sync.Mutex
	calls      int
	overlapped bool
	active     func() int
}

func (f *activeCheckingCacheCleaner) Cleanup(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.active() != 0 {
		f.overlapped = true
	}
	return nil
}

func (f *activeCheckingCacheCleaner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *activeCheckingCacheCleaner) didOverlap() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.overlapped
}

type errImageRunner struct {
	mu       sync.Mutex
	images   []string
	findings map[string][]model.Finding
	errs     map[string]error
}

func (r *errImageRunner) ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error) {
	r.mu.Lock()
	r.images = append(r.images, image)
	r.mu.Unlock()
	if err, ok := r.errs[image]; ok {
		return nil, err
	}
	return r.findings[image], nil
}

type parentCancelingImageRunner struct {
	cancel context.CancelFunc
	err    error
}

func (r *parentCancelingImageRunner) ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error) {
	r.cancel()
	return nil, r.err
}

type blockingImageRunner struct {
	mu       sync.Mutex
	findings map[string][]model.Finding
	started  map[string]chan struct{}
	releaseC map[string]chan struct{}
	active   int
	max      int
}

func newBlockingImageRunner(findings map[string][]model.Finding) *blockingImageRunner {
	started := make(map[string]chan struct{}, len(findings))
	releaseC := make(map[string]chan struct{}, len(findings))
	for image := range findings {
		started[image] = make(chan struct{})
		releaseC[image] = make(chan struct{})
	}
	return &blockingImageRunner{
		findings: findings,
		started:  started,
		releaseC: releaseC,
	}
}

func (r *blockingImageRunner) ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error) {
	r.mu.Lock()
	r.active++
	if r.active > r.max {
		r.max = r.active
	}
	close(r.started[image])
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.releaseC[image]:
	}

	return r.findings[image], nil
}

func (r *blockingImageRunner) release(image string) {
	close(r.releaseC[image])
}

func (r *blockingImageRunner) waitUntilStarted(t *testing.T, image string) {
	t.Helper()
	select {
	case <-r.started[image]:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s to start", image)
	}
}

func (r *blockingImageRunner) waitUntilActive(t *testing.T, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d active scans", want)
		case <-ticker.C:
			r.mu.Lock()
			active := r.active
			r.mu.Unlock()
			if active == want {
				return
			}
		}
	}
}

func (r *blockingImageRunner) maxActive() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
}

func (r *blockingImageRunner) activeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}
