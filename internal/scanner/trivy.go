package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/model"
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

	args := []string{"image", "--format", "json", "--scanners", "vuln", "--timeout", timeout.String(), image}
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
