package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/matthewvenne/trivy-plugin-vdr/internal/model"
)

const defaultTrivyBinary = "trivy"

type Runner interface {
	ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error)
}

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

type TrivyRunner struct {
	Binary        string
	ImageSrc      string
	CommandRunner CommandRunner
}

func (r TrivyRunner) ScanImage(ctx context.Context, image string, timeout time.Duration) ([]model.Finding, error) {
	binary := r.Binary
	if binary == "" {
		binary = defaultTrivyBinary
	}
	commandRunner := r.CommandRunner
	if commandRunner == nil {
		commandRunner = execCommandRunner{}
	}

	imageSrc := r.ImageSrc
	if imageSrc == "" {
		imageSrc = "registry"
	}

	args := []string{"image", "--image-src", imageSrc, "--format", "json", "--scanners", "vuln", "--timeout", timeout.String(), image}
	stdout, stderr, err := commandRunner.Run(ctx, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("trivy image scan failed for %q: %w: %s", image, err, string(bytes.TrimSpace(stderr)))
	}

	findings, err := parseTrivyFindings(stdout, image)
	if err != nil {
		return nil, err
	}
	return findings, nil
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
		parallelScans = 1
	}

	jobs := make(chan int)
	results := make([]scanResult, len(images))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for worker := 0; worker < parallelScans; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				image := images[index]
				findings, err := runner.ScanImage(ctx, image.ImageRef, options.Timeout)
				result := scanResult{findings: findings, err: err}
				if err == nil {
					for i := range result.findings {
						result.findings[i].ImageRef = image.ImageRef
						if image.NormalizedImage != "" {
							result.findings[i].NormalizedImage = image.NormalizedImage
						}
						result.findings[i].AffectedResources = append([]model.ResourceRef(nil), image.Resources...)
					}
					if options.CacheCleanup != CleanupNever && options.CacheCleaner != nil {
						if cleanupErr := options.CacheCleaner.Cleanup(ctx); cleanupErr != nil {
							result.warnings = append(result.warnings, Warning{
								ImageRef: image.ImageRef,
								Message:  fmt.Sprintf("trivy cache cleanup failed after scanning %q: %v", image.ImageRef, cleanupErr),
							})
						}
					}
				}
				results[index] = result
				if err != nil {
					cancel()
				}
			}
		}()
	}

	for index := range images {
		select {
		case <-ctx.Done():
			break
		case jobs <- index:
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()

	var findings []model.Finding
	var warnings []Warning
	for _, result := range results {
		if result.err != nil {
			return nil, nil, result.err
		}
		findings = append(findings, result.findings...)
		warnings = append(warnings, result.warnings...)
	}
	return findings, warnings, nil
}

type scanResult struct {
	findings []model.Finding
	warnings []Warning
	err      error
}

type inventoryImage struct {
	ImageRef        string
	NormalizedImage string
	Resources       []model.ResourceRef
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
			})
			continue
		}

		if images[index].NormalizedImage == "" {
			images[index].NormalizedImage = image.NormalizedImage
		}
		images[index].Resources = append(images[index].Resources, image.Resources...)
	}
	return images
}

func parseTrivyFindings(data []byte, image string) ([]model.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse trivy JSON for %q: %w", image, err)
	}

	var findings []model.Finding
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			findings = append(findings, model.Finding{
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
			})
		}
	}
	return findings, nil
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Status           string   `json:"Status"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	References       []string `json:"References"`
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
