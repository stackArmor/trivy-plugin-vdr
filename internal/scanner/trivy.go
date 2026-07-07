package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/distribution/reference"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const defaultTrivyBinary = "trivy"
const defaultParallelScans = 5

var defaultImageScanRetryDelays = []time.Duration{2 * time.Second, 5 * time.Second}

type Runner interface {
	ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error)
}

type OptionRunner interface {
	ScanImageWithOptions(ctx context.Context, image string, timeout time.Duration, options ScanImageOptions) ([]model.Finding, error)
}

type ScanImageOptions struct {
	SkipDirs []string
}

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

type TrivyRunner struct {
	Binary          string
	ImageSrc        string
	CacheDir        string
	DockerConfigDir string
	// OCIVEXIncluded enables --vex oci for every scanned image.
	OCIVEXIncluded bool
	// VEXOCIRegistries enables --vex oci for images whose registry/repository
	// matches one of these allowlist entries. Host-only entries match the registry
	// host; host/path entries match that repository prefix.
	VEXOCIRegistries []string
	// SkipDBUpdate passes --skip-db-update to each scan. Set this only after the
	// vulnerability DB has been downloaded once via EnsureVulnDB so scans reuse
	// it instead of each re-checking for an update.
	SkipDBUpdate  bool
	CommandRunner CommandRunner
	// Logger receives self-heal notices. Optional.
	Logger *log.Logger
	// healOnce, when non-nil, enables one-shot cache self-healing: if a scan
	// fails with a corrupted/locked Trivy cache, the cache is cleared and the DB
	// re-downloaded once, then the scan is retried. Shared across all scans.
	healOnce *sync.Once
	// workerCaches, when non-nil, hands out an isolated cache directory per scan
	// so concurrent scans don't contend on a shared scan-cache lock.
	workerCaches *workerCachePool
}

// WithSelfHeal returns a copy of the runner with one-shot cache self-healing
// enabled, sharing heal state so the cache is repaired at most once per run.
func (r TrivyRunner) WithSelfHeal() TrivyRunner {
	r.healOnce = &sync.Once{}
	return r
}

func (r TrivyRunner) binary() string {
	if r.Binary == "" {
		return defaultTrivyBinary
	}
	return r.Binary
}

func (r TrivyRunner) commandRunner() CommandRunner {
	if r.CommandRunner != nil {
		return r.CommandRunner
	}
	return execCommandRunner{extraEnv: r.dockerEnv()}
}

// EnsureDatabases downloads/updates the Trivy vulnerability database and the
// Java index database once up front so per-image scans can run with
// --skip-db-update --skip-java-db-update and share the cache safely. Downloading
// these mid-scan (the Java DB is ~900MB) is what corrupts a shared cache when
// scans run concurrently, so doing it once before scanning makes parallel scans
// against a single cache directory safe.
func (r TrivyRunner) EnsureDatabases(ctx context.Context) error {
	if err := r.downloadDB(ctx, "--download-db-only"); err != nil {
		return fmt.Errorf("vulnerability DB: %w", err)
	}
	if err := r.downloadDB(ctx, "--download-java-db-only"); err != nil {
		return fmt.Errorf("Java DB: %w", err)
	}
	return nil
}

func (r TrivyRunner) downloadDB(ctx context.Context, downloadFlag string) error {
	args := []string{"image", downloadFlag, "--skip-version-check"}
	if r.CacheDir != "" {
		args = append(args, "--cache-dir", r.CacheDir)
	}
	_, stderr, err := r.commandRunner().Run(ctx, r.binary(), args...)
	if err != nil {
		return fmt.Errorf("trivy %s failed: %w: %s", downloadFlag, err, string(bytes.TrimSpace(stderr)))
	}
	return nil
}

func (r TrivyRunner) ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error) {
	return r.ScanImageWithOptions(ctx, image, timeout, ScanImageOptions{})
}

func (r TrivyRunner) ScanImageWithOptions(ctx context.Context, image string, timeout time.Duration, options ScanImageOptions) ([]model.Finding, error) {
	// With isolated worker caches, acquire one for the duration of this scan so
	// each concurrent scan writes to its own fs (fanal) cache.
	cacheDir := r.CacheDir
	if r.workerCaches != nil {
		d := <-r.workerCaches.free
		defer func() { r.workerCaches.free <- d }()
		cacheDir = d
	}

	findings, err := r.scanOnce(ctx, cacheDir, image, timeout, options)
	if err != nil && r.useOCIVEX(image) && looksLikeOCIVEXRetrievalFailure(err) {
		if r.Logger != nil {
			r.Logger.Warn("OCI VEX lookup failed for %s; retrying vulnerability scan without OCI VEX: %v", image, err)
		}
		retry := r
		retry.OCIVEXIncluded = false
		retry.VEXOCIRegistries = nil
		findings, err = retry.scanOnce(ctx, cacheDir, image, timeout, options)
	}
	if err == nil || r.healOnce == nil || !looksLikeCacheCorruption(err) {
		return findings, err
	}
	// One-shot cache self-heal: a corrupted database fails every scan until
	// cleared. Repair it once (shared across workers) and retry.
	r.healOnce.Do(func() {
		r.Logger.Warn("detected a corrupted Trivy database; clearing and re-downloading")
		if healErr := r.healCache(ctx); healErr != nil {
			r.Logger.Error("cache self-heal failed: %v", healErr)
		} else {
			r.Logger.Info("Trivy database repaired")
		}
	})
	return r.scanOnce(ctx, cacheDir, image, timeout, options)
}

func (r TrivyRunner) scanOnce(ctx context.Context, cacheDir, image string, timeout time.Duration, options ScanImageOptions) ([]model.Finding, error) {
	imageSrc := r.ImageSrc
	if imageSrc == "" {
		imageSrc = "remote"
	}

	args := []string{"image"}
	if cacheDir != "" {
		args = append(args, "--cache-dir", cacheDir)
	}
	if r.SkipDBUpdate {
		args = append(args, "--skip-db-update", "--skip-java-db-update")
	}
	args = append(args, "--image-src", imageSrc, "--skip-version-check", "--format", "json", "--scanners", "vuln")
	if r.useOCIVEX(image) {
		args = append(args, "--vex", "oci", "--show-suppressed")
	}
	for _, dir := range options.SkipDirs {
		if dir == "" {
			continue
		}
		args = append(args, "--skip-dir", dir)
	}
	args = append(args, "--timeout", timeout.String(), image)
	stdout, stderr, err := r.commandRunner().Run(ctx, r.binary(), args...)
	if err != nil {
		return nil, fmt.Errorf("trivy image scan failed for %q: %w: %s", image, err, string(bytes.TrimSpace(stderr)))
	}

	findings, err := parseTrivyFindings(stdout, image)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (r TrivyRunner) useOCIVEX(image string) bool {
	if r.OCIVEXIncluded {
		return true
	}
	if len(r.VEXOCIRegistries) == 0 {
		return false
	}
	ref, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return false
	}
	domain := reference.Domain(ref)
	path := reference.Path(ref)
	repository := domain
	if path != "" {
		repository += "/" + path
	}
	for _, allowed := range r.VEXOCIRegistries {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if !strings.Contains(allowed, "/") {
			if domain == allowed {
				return true
			}
			continue
		}
		if repository == allowed || strings.HasPrefix(repository, allowed+"/") {
			return true
		}
	}
	return false
}

func looksLikeOCIVEXRetrievalFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "vex oci") &&
		(strings.Contains(msg, "failed to retrieve vex attestation") ||
			strings.Contains(msg, "fetching attestations") ||
			strings.Contains(msg, "blob_unknown") ||
			strings.Contains(msg, "unknown blob"))
}

// workerCachePool hands out isolated Trivy cache directories so concurrent scans
// don't contend on a shared fs (fanal) cache lock. Each directory shares the
// vulnerability and Java databases with the base cache via hardlinks (no extra
// disk) but has its own scan cache.
type workerCachePool struct {
	free chan string
	dirs []string
}

func (p *workerCachePool) remove() {
	for _, dir := range p.dirs {
		os.RemoveAll(dir)
	}
}

// PrepareWorkerCaches builds n isolated cache directories (DBs hardlinked from
// the base cache) and returns a runner that hands them out per scan, plus a
// cleanup func. With n <= 1 or no CacheDir it is a no-op. Call after
// EnsureDatabases so the databases exist to hardlink.
func (r TrivyRunner) PrepareWorkerCaches(n int) (TrivyRunner, func(), error) {
	if n <= 1 || r.CacheDir == "" {
		return r, func() {}, nil
	}
	pool := &workerCachePool{free: make(chan string, n)}
	for i := 0; i < n; i++ {
		dir, err := r.makeWorkerCache()
		if err != nil {
			pool.remove()
			return r, func() {}, err
		}
		pool.dirs = append(pool.dirs, dir)
		pool.free <- dir
	}
	r.workerCaches = pool
	return r, pool.remove, nil
}

func (r TrivyRunner) makeWorkerCache() (string, error) {
	dir, err := os.MkdirTemp(r.CacheDir, "worker-")
	if err != nil {
		return "", err
	}
	for _, sub := range []string{"db", "java-db"} {
		src := filepath.Join(r.CacheDir, sub)
		entries, err := os.ReadDir(src)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Java DB may be absent until a Java image is scanned.
			}
			os.RemoveAll(dir)
			return "", err
		}
		dst := filepath.Join(dir, sub)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if err := os.Link(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
				os.RemoveAll(dir)
				return "", err
			}
		}
	}
	return dir, nil
}

// healCache removes the Trivy database subdirectories and re-downloads them,
// leaving the scan cache (fanal) and enrichment caches (epss, vulnrichment)
// untouched so concurrent scans are not disrupted.
func (r TrivyRunner) healCache(ctx context.Context) error {
	if r.CacheDir == "" {
		return nil
	}
	for _, sub := range []string{"db", "java-db"} {
		if err := os.RemoveAll(filepath.Join(r.CacheDir, sub)); err != nil {
			return err
		}
	}
	return r.EnsureDatabases(ctx)
}

// looksLikeCacheCorruption reports whether an error indicates a genuinely
// corrupted database that a re-download could fix. It deliberately excludes
// transient cache-lock contention ("cache may be in use", "unable to initialize
// fs cache"), which is not corruption and must not trigger a destructive
// clear+redownload that would disrupt other in-flight scans.
func looksLikeCacheCorruption(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sig := range []string{
		"unexpected fault",
		"sigsegv",
		"segmentation violation",
		"bbolt",
		"invalid database",
		"panic:",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

type CacheCleaner interface {
	Cleanup(ctx context.Context) error
}

type CleanupPolicy string

const (
	CleanupAuto   CleanupPolicy = "auto"
	CleanupAlways CleanupPolicy = "always"
	CleanupNever  CleanupPolicy = "never"
)

type Warning struct {
	ImageRef string
	Message  string
}

type ScanOptions struct {
	Timeout             time.Duration
	ParallelScans       int
	CacheCleanup        CleanupPolicy
	CacheDir            string
	CacheMinFreeGB      int
	CacheMinFreePercent int
	CacheCleaner        CacheCleaner
	Logger              *log.Logger
	RetryDelays         []time.Duration
}

func ScanInventory(ctx context.Context, inventory *model.Inventory, runner Runner, timeout time.Duration) ([]model.Finding, error) {
	if inventory == nil {
		return nil, nil
	}

	images := orderedInventoryImages(inventory)
	var findings []model.Finding
	for _, image := range images {
		scanned, err := runner.ScanImage(ctx, image.ImageRef, timeout)
		if err != nil {
			return nil, err
		}
		for _, finding := range scanned {
			finding.ImageRef = image.ImageRef
			if image.NormalizedImage != "" {
				finding.NormalizedImage = image.NormalizedImage
			}
			finding.AffectedResources = append([]model.ResourceRef(nil), image.Resources...)
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func ScanInventoryWithOptions(ctx context.Context, inventory *model.Inventory, runner Runner, options ScanOptions) ([]model.Finding, []Warning, error) {
	if inventory == nil {
		return nil, nil, nil
	}
	if options.CacheCleanup == "" {
		options.CacheCleanup = CleanupAuto
	}
	if options.CacheCleanup != CleanupNever && options.CacheCleaner == nil {
		options.CacheCleaner = NewCacheCleaner(CacheCleanupOptions{
			Policy:         options.CacheCleanup,
			CacheDir:       options.CacheDir,
			MinFreeGB:      options.CacheMinFreeGB,
			MinFreePercent: options.CacheMinFreePercent,
		})
	}
	images := orderedInventoryImages(inventory)
	sort.SliceStable(images, func(i, j int) bool {
		return images[i].ImageRef < images[j].ImageRef
	})

	parallelScans := options.ParallelScans
	if parallelScans <= 0 {
		parallelScans = defaultParallelScans
	}
	retryDelays := options.RetryDelays
	if retryDelays == nil {
		retryDelays = defaultImageScanRetryDelays
	}

	jobs := make(chan int)
	results := make([]scanResult, len(images))
	parentCtx := ctx
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	total := len(images)
	var done atomic.Int64

	scanIndex := func(index int) {
		image := images[index]
		options.Logger.Info("scanning %s", image.ImageRef)
		findings, err := scanInventoryImageWithRetry(ctx, runner, image, options.Timeout, retryDelays, options.Logger)
		result := scanResult{findings: findings, err: err, completed: err == nil}
		if err == nil {
			for i := range result.findings {
				result.findings[i].ImageRef = image.ImageRef
				if image.NormalizedImage != "" {
					result.findings[i].NormalizedImage = image.NormalizedImage
				}
				result.findings[i].AffectedResources = append([]model.ResourceRef(nil), image.Resources...)
			}
		}
		results[index] = result
		// A single image failure is recorded and surfaced as a warning; it does
		// not cancel sibling scans or abort the run.
		n := done.Add(1)
		if err != nil {
			options.Logger.Warn("[%d/%d] %s failed: %v", n, total, image.ImageRef, err)
		} else {
			options.Logger.Info("[%d/%d] %s: %d findings", n, total, image.ImageRef, len(findings))
		}
	}

	var wg sync.WaitGroup
	for worker := 0; worker < parallelScans; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				scanIndex(index)
			}
		}()
	}
	for index := 0; index < total; index++ {
		select {
		case <-ctx.Done():
		case jobs <- index:
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()

	// The derived ctx is only cancelled when the parent is, so any cancellation
	// here means the caller aborted the whole run.
	if parentErr := parentCtx.Err(); parentErr != nil {
		return nil, nil, parentErr
	}

	var cleanupWarnings []Warning
	if options.CacheCleanup != CleanupNever && options.CacheCleaner != nil && completedScanCount(results) > 0 {
		if cleanupErr := options.CacheCleaner.Cleanup(ctx); cleanupErr != nil {
			if parentErr := parentCtx.Err(); parentErr != nil {
				return nil, nil, parentErr
			}
			if isContextError(cleanupErr) {
				return nil, nil, cleanupErr
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			cleanupWarnings = append(cleanupWarnings, Warning{
				Message: fmt.Sprintf("trivy cache cleanup failed after scanning inventory: %v", cleanupErr),
			})
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			if parentErr := parentCtx.Err(); parentErr != nil {
				return nil, nil, parentErr
			}
			return nil, nil, ctxErr
		}
	}

	var findings []model.Finding
	var warnings []Warning
	for index, result := range results {
		if result.err != nil {
			warnings = append(warnings, Warning{
				ImageRef: images[index].ImageRef,
				Message:  fmt.Sprintf("image scan failed: %v", result.err),
			})
			continue
		}
		findings = append(findings, result.findings...)
		warnings = append(warnings, result.warnings...)
	}
	warnings = append(warnings, cleanupWarnings...)
	return findings, warnings, nil
}

func completedScanCount(results []scanResult) int {
	var count int
	for _, result := range results {
		if result.completed {
			count++
		}
	}
	return count
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

type scanResult struct {
	findings  []model.Finding
	warnings  []Warning
	err       error
	completed bool
}

type inventoryImage struct {
	ImageRef        string
	NormalizedImage string
	Resources       []model.ResourceRef
	SkipDirs        []string
}

func orderedInventoryImages(inventory *model.Inventory) []inventoryImage {
	seen := map[string]int{}
	var images []inventoryImage
	for _, image := range inventory.Images {
		if image.ImageRef == "" {
			continue
		}
		index, ok := seen[image.ImageRef]
		if !ok {
			seen[image.ImageRef] = len(images)
			images = append(images, inventoryImage{
				ImageRef:        image.ImageRef,
				NormalizedImage: image.NormalizedImage,
				Resources:       append([]model.ResourceRef(nil), image.Resources...),
				SkipDirs:        append([]string(nil), image.SkipDirs...),
			})
			continue
		}

		if images[index].NormalizedImage == "" {
			images[index].NormalizedImage = image.NormalizedImage
		}
		images[index].Resources = append(images[index].Resources, image.Resources...)
		images[index].SkipDirs = mergeStrings(images[index].SkipDirs, image.SkipDirs)
	}
	return images
}

func scanInventoryImage(ctx context.Context, runner Runner, image inventoryImage, timeout time.Duration) ([]model.Finding, error) {
	if optionRunner, ok := runner.(OptionRunner); ok {
		return optionRunner.ScanImageWithOptions(ctx, image.ImageRef, timeout, ScanImageOptions{
			SkipDirs: append([]string(nil), image.SkipDirs...),
		})
	}
	return runner.ScanImage(ctx, image.ImageRef, timeout)
}

func scanInventoryImageWithRetry(ctx context.Context, runner Runner, image inventoryImage, timeout time.Duration, retryDelays []time.Duration, logger *log.Logger) ([]model.Finding, error) {
	totalAttempts := len(retryDelays) + 1
	for attempt := 1; ; attempt++ {
		findings, err := scanInventoryImage(ctx, runner, image, timeout)
		if err == nil {
			return findings, nil
		}
		if attempt >= totalAttempts || !looksLikeTransientImageScanFailure(err) || isContextError(err) {
			return nil, err
		}
		delay := retryDelays[attempt-1]
		logger.Warn("%s scan attempt %d/%d failed; retrying in %s: %v", image.ImageRef, attempt, totalAttempts, delay, err)
		if waitErr := waitRetryDelay(ctx, delay); waitErr != nil {
			return nil, waitErr
		}
	}
}

func looksLikeTransientImageScanFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sig := range []string{
		"unexpected eof",
		"connection reset",
		"connection refused",
		"i/o timeout",
		"tls handshake timeout",
		"timeout awaiting response headers",
		"temporary failure",
		"temporarily unavailable",
		"too many requests",
		"429",
		"500 internal server",
		"502 bad gateway",
		"503 service unavailable",
		"504 gateway timeout",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

func waitRetryDelay(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func mergeStrings(existing, added []string) []string {
	if len(added) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(added))
	result := append([]string(nil), existing...)
	for _, value := range result {
		seen[value] = struct{}{}
	}
	for _, value := range added {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func parseTrivyFindings(data []byte, image string) ([]model.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse trivy JSON for %q: %w", image, err)
	}

	var findings []model.Finding
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			findings = append(findings, findingFromTrivyVulnerability(vulnerability, image))
		}
		for _, modified := range result.ModifiedFindings {
			if modified.Type != "" && modified.Type != "vulnerability" {
				continue
			}
			finding := findingFromTrivyVulnerability(modified.Finding, image)
			finding.Suppressed = true
			finding.Suppression = &model.Suppression{
				Source:          "vex",
				Status:          modified.Status,
				Justification:   modified.Statement,
				StatementSource: modified.Source,
			}
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func findingFromTrivyVulnerability(vulnerability trivyVulnerability, image string) model.Finding {
	return model.Finding{
		ID:               vulnerability.VulnerabilityID,
		ImageRef:         image,
		PackageName:      vulnerability.PkgName,
		InstalledVersion: vulnerability.InstalledVersion,
		FixedVersion:     vulnerability.FixedVersion,
		Severity:         vulnerability.Severity,
		Status:           vulnerability.Status,
		Title:            vulnerability.Title,
		Description:      vulnerability.Description,
		References:       append([]string(nil), vulnerability.References...),
		CVSSVector:       bestCVSSVector(vulnerability.CVSS),
	}
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Vulnerabilities  []trivyVulnerability   `json:"Vulnerabilities"`
	ModifiedFindings []trivyModifiedFinding `json:"ExperimentalModifiedFindings"`
}

type trivyVulnerability struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgName          string               `json:"PkgName"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Severity         string               `json:"Severity"`
	Status           string               `json:"Status"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	References       []string             `json:"References"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
}

type trivyModifiedFinding struct {
	Type      string             `json:"Type"`
	Status    string             `json:"Status"`
	Statement string             `json:"Statement"`
	Source    string             `json:"Source"`
	Finding   trivyVulnerability `json:"Finding"`
}

type trivyCVSS struct {
	V3Vector  string `json:"V3Vector"`
	V40Vector string `json:"V40Vector"`
}

// bestCVSSVector returns a single CVSS base vector, preferring NVD, then Red Hat,
// then GHSA, then any remaining source in a deterministic order. v3 vectors are
// preferred over v4 because the report's automatability heuristic is expressed in
// v3 base metrics (the AV/AC/PR/UI metric names are shared by both versions).
func bestCVSSVector(cvss map[string]trivyCVSS) string {
	if len(cvss) == 0 {
		return ""
	}
	preferred := []string{"nvd", "redhat", "ghsa"}
	pick := func(get func(trivyCVSS) string) string {
		for _, vendor := range preferred {
			if c, ok := cvss[vendor]; ok {
				if v := get(c); v != "" {
					return v
				}
			}
		}
		keys := make([]string, 0, len(cvss))
		for key := range cvss {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if v := get(cvss[key]); v != "" {
				return v
			}
		}
		return ""
	}
	if v := pick(func(c trivyCVSS) string { return c.V3Vector }); v != "" {
		return v
	}
	return pick(func(c trivyCVSS) string { return c.V40Vector })
}

// dockerEnv returns the DOCKER_CONFIG environment entry that points Trivy at the
// generated registry credentials, or nil when no credentials were assembled.
func (r TrivyRunner) dockerEnv() []string {
	if r.DockerConfigDir == "" {
		return nil
	}
	return []string{"DOCKER_CONFIG=" + r.DockerConfigDir}
}

type execCommandRunner struct {
	extraEnv []string
}

func (r execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(r.extraEnv) > 0 {
		cmd.Env = append(os.Environ(), r.extraEnv...)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
