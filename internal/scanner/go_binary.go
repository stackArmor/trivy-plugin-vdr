package scanner

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stackArmor/trivy-plugin-vdr/internal/log"
)

type trivyImageMetadata struct {
	ImageID     string      `json:"ImageID"`
	RepoDigests []string    `json:"RepoDigests"`
	ImageConfig v1.Platform `json:"ImageConfig"`
}

const goBinaryTempLimit int64 = 5 << 30

// GoBinaryFilter shares helper slots, temporary disk reservations and metrics
// across all image workers for one invocation.
type GoBinaryFilter struct {
	slots                     chan struct{}
	minFreeGB, minFreePercent int
	mu                        sync.Mutex
	reserved, peak            int64
	imageTime                 time.Duration
	omitted                   int
	skips                     map[string]int
}

func NewGoBinaryFilter(minFreeGB, minFreePercent int) *GoBinaryFilter {
	return &GoBinaryFilter{
		slots:          make(chan struct{}, 2),
		minFreeGB:      minFreeGB,
		minFreePercent: minFreePercent,
		skips:          make(map[string]int),
	}
}

func (f *GoBinaryFilter) LogSummary(logger *log.Logger) {
	f.mu.Lock()
	defer f.mu.Unlock()
	logger.Info("Go binary filter: cumulative image time=%s peak reserved bytes=%d omitted findings=%d skipped binaries by reason=%v", f.imageTime.Round(time.Millisecond), f.peak, f.omitted, f.skips)
}

var errTempSpace = errors.New("Go binary temporary space limit reached")

func (f *GoBinaryFilter) reserve(dir string, size int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if size < 0 || size > goBinaryTempLimit-f.reserved {
		return errTempSpace
	}
	space, err := (statfsDiskSpaceProvider{}).DiskSpace(dir)
	if err != nil {
		return err
	}
	floor := max(uint64(f.minFreeGB)<<30, space.TotalBytes/100*uint64(f.minFreePercent))
	// The other worker may still be writing its reserved file.
	required := uint64(f.reserved + size)
	if required > space.FreeBytes || space.FreeBytes-required < floor {
		return errTempSpace
	}
	f.reserved += size
	f.peak = max(f.peak, f.reserved)
	return nil
}

func (f *GoBinaryFilter) release(size int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reserved -= size
}

func goVulncheckPath() (string, error) {
	if exe, err := os.Executable(); err == nil {
		if bundled, err := exec.LookPath(filepath.Join(filepath.Dir(exe), "govulncheck")); err == nil {
			return bundled, nil
		}
	}
	return exec.LookPath("govulncheck")
}

func (r TrivyRunner) filterGoBinaryFindings(ctx context.Context, image string, report *trivyReport) {
	// Trivy identifies which layer furnished each executable and which path it
	// scanned. Fetch those layers once, even when they contain several binaries.
	targets := make(map[string]map[string]bool)
	missingLayer := make(map[string]bool)
	for _, result := range report.Results {
		if result.Type != "gobinary" {
			continue
		}
		for _, vuln := range result.Vulnerabilities {
			digest := vuln.Layer.Digest
			if digest == "" {
				missingLayer[result.Target] = true
				continue
			}
			if targets[digest] == nil {
				targets[digest] = make(map[string]bool)
			}
			targets[digest][imageFilePath(result.Target)] = true
		}
	}
	f := r.GoBinaryFilter
	if len(missingLayer) > 0 {
		f.mu.Lock()
		f.skips["missing_layer"] += len(missingLayer)
		f.mu.Unlock()
	}
	if len(targets) == 0 {
		return
	}
	start := time.Now()
	total, omitted, checked := 0, 0, 0
	for _, paths := range targets {
		total += len(paths)
	}
	skips := make(map[string]int)
	defer func() {
		reason := "unavailable"
		if ctx.Err() != nil {
			reason = "deadline_or_cancel"
		}
		for _, n := range skips {
			total -= n
		}
		if total > checked {
			skips[reason] += total - checked
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.imageTime += time.Since(start)
		f.omitted += omitted
		for reason, count := range skips {
			f.skips[reason] += count
		}
	}()
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	case <-ctx.Done():
		return
	}
	scanner, err := goVulncheckPath()
	if err != nil {
		r.Logger.Warn("Go binary filter for %s: %v", image, err)
		return
	}
	artifact, err := r.goBinaryImage(ctx, image, report.Metadata)
	if err != nil {
		r.Logger.Warn("Go binary filter for %s: %v", image, err)
		return
	}
	for digest, paths := range targets {
		if ctx.Err() != nil {
			break
		}
		proofs, err := r.scanGoLayer(ctx, scanner, artifact, digest, paths)
		if err != nil {
			r.Logger.Warn("Go binary filter for %s: read layer %s: %v", image, digest, err)
			continue
		}
		for _, result := range proofs {
			if result.proof != nil {
				checked++
			} else {
				skips[result.reason]++
			}
		}
		for i := range report.Results {
			result := &report.Results[i]
			if result.Type != "gobinary" {
				continue
			}
			proof := proofs[imageFilePath(result.Target)].proof
			if proof == nil {
				continue
			}
			original := len(result.Vulnerabilities)
			result.Vulnerabilities = slices.DeleteFunc(result.Vulnerabilities, func(v trivyVulnerability) bool {
				return v.Layer.Digest == digest && proof.canOmit(v)
			})
			omitted += original - len(result.Vulnerabilities)
		}
	}
}

func (r TrivyRunner) goBinaryImage(ctx context.Context, image string, metadata trivyImageMetadata) (v1.Image, error) {
	if metadata.ImageID == "" || metadata.ImageConfig.OS == "" || metadata.ImageConfig.Architecture == "" {
		return nil, errors.New("Trivy did not report the scanned image identity and platform")
	}
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}
	var pinned name.Digest
	for _, digest := range metadata.RepoDigests {
		candidate, err := name.NewDigest(digest)
		if err == nil && candidate.Context().Name() == ref.Context().Name() {
			pinned = candidate
			break
		}
	}
	if pinned.DigestStr() == "" {
		return nil, errors.New("Trivy did not report a digest for the scanned repository")
	}
	auth := remote.WithAuthFromKeychain(authn.DefaultKeychain)
	host := pinned.Context().RegistryStr()
	if host == name.DefaultRegistry {
		host = "docker.io"
	}
	if creds, ok := r.RegistryAuths[host]; ok {
		auth = remote.WithAuth(authn.FromConfig(authn.AuthConfig{
			Username: creds.Username,
			Password: creds.Password,
			Auth:     creds.Auth,
		}))
	}
	artifact, err := remote.Image(pinned, auth, remote.WithContext(ctx), remote.WithPlatform(metadata.ImageConfig))
	if err != nil {
		return nil, err
	}
	config, err := artifact.ConfigName()
	if err != nil {
		return nil, err
	}
	if config.String() != metadata.ImageID {
		return nil, errors.New("registry image config differs from the one Trivy scanned")
	}
	return artifact, nil
}

func imageFilePath(filename string) string {
	return path.Clean(strings.TrimPrefix(filename, "/"))
}

type goTargetResult struct {
	proof  *goBinaryEvidence
	reason string
}

func (r TrivyRunner) scanGoLayer(ctx context.Context, scanner string, image v1.Image, digest string, paths map[string]bool) (map[string]goTargetResult, error) {
	hash, err := v1.NewHash(digest)
	if err != nil {
		return nil, err
	}
	layer, err := image.LayerByDigest(hash)
	if err != nil {
		return nil, err
	}
	stream, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	archive := tar.NewReader(stream)
	results := make(map[string]goTargetResult, len(paths))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		target := imageFilePath(header.Name)
		if !paths[target] {
			continue
		}
		if _, seen := results[target]; seen || header.Typeflag != tar.TypeReg {
			results[target] = goTargetResult{reason: "ambiguous_or_nonregular"}
			continue
		}
		proof, err := r.GoBinaryFilter.scanEntry(ctx, scanner, archive, header.Size)
		result := goTargetResult{proof: proof}
		if err != nil {
			result.reason = "scan_error"
			if errors.Is(err, errTempSpace) {
				result.reason = "disk_limit"
			}
			r.Logger.Warn("Go binary filter for %s (%s): %v", digest, target, err)
		}
		results[target] = result
	}
	// Only publish evidence after checking for duplicate paths and allowing
	// the registry reader to verify the complete layer.
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return nil, err
	}
	return results, nil
}

func (f *GoBinaryFilter) scanEntry(ctx context.Context, scanner string, entry io.Reader, size int64) (proof *goBinaryEvidence, err error) {
	dir := os.TempDir()
	if err := f.reserve(dir, size); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(dir, "vdr-go-binary-*")
	if err != nil {
		f.release(size)
		return nil, err
	}
	defer func() {
		if removeErr := os.Remove(file.Name()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			// Keep accounting for a file we could not reclaim.
			proof, err = nil, errors.Join(err, removeErr)
			return
		}
		f.release(size)
	}()
	_, copyErr := io.CopyN(file, entry, size)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return nil, err
	}
	return scanGoBinary(ctx, scanner, file.Name())
}

func scanGoBinary(ctx context.Context, scanner, file string) (*goBinaryEvidence, error) {
	if file == "" {
		return nil, errors.New("could not identify a unique regular file in the image layer")
	}
	build, err := buildinfo.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var os, arch string
	for _, setting := range build.Settings {
		switch setting.Key {
		case "GOOS":
			os = setting.Value
		case "GOARCH":
			arch = setting.Value
		}
	}
	stdout, stderr, err := (execCommandRunner{}).Run(ctx, scanner, "-mode=binary", "-format=json", file)
	if err != nil {
		return nil, fmt.Errorf("govulncheck: %w: %s", err, bytes.TrimSpace(stderr))
	}
	return readGoBinaryEvidence(bytes.NewReader(stdout), os, arch)
}

type goBinaryEvidence struct {
	os, arch     string
	modules      map[string]string
	advisories   map[string][]*goAdvisory
	moduleHits   map[string]map[goModule]bool
	functionHits map[string]bool
}

type goModule struct {
	Path string `json:"path"
 "path/filepath"
 "sync"
 "github.com/stackArmor/trivy-plugin-vdr/internal/log"`
	Version string `json:"version"`
}

type goAdvisory struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []struct {
				Path string `json:"path"
 "path/filepath"
 "sync"
 "github.com/stackArmor/trivy-plugin-vdr/internal/log"`
				GOOS   []string `json:"goos"`
				GOARCH []string `json:"goarch"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

func readGoBinaryEvidence(data io.Reader, os, arch string) (*goBinaryEvidence, error) {
	evidence := &goBinaryEvidence{
		os: os, arch: arch,
		modules:      make(map[string]string),
		advisories:   make(map[string][]*goAdvisory),
		moduleHits:   make(map[string]map[goModule]bool),
		functionHits: make(map[string]bool),
	}
	advisories := make(map[string]*goAdvisory)
	decoder := json.NewDecoder(data)
	gotConfig := false
	for {
		var message struct {
			Config *struct {
				Protocol string `json:"protocol_version"`
				Mode     string `json:"scan_mode"`
				Level    string `json:"scan_level"`
			} `json:"config"`
			SBOM *struct {
				Modules []goModule `json:"modules"`
			} `json:"SBOM"`
			OSV     *goAdvisory `json:"osv"`
			Finding *struct {
				OSV   string `json:"osv"`
				Trace []struct {
					Module   string `json:"module"`
					Version  string `json:"version"`
					Package  string `json:"package"`
					Function string `json:"function"`
				} `json:"trace"`
			} `json:"finding"`
		}
		if err := decoder.Decode(&message); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parse govulncheck JSON: %w", err)
		}
		switch {
		case message.Config != nil:
			cfg := message.Config
			if cfg.Protocol != "v1.0.0" || cfg.Mode != "binary" || cfg.Level != "symbol" {
				return nil, errors.New("govulncheck did not report a supported binary symbol scan")
			}
			gotConfig = true
		case message.SBOM != nil:
			for _, module := range message.SBOM.Modules {
				evidence.modules[module.Path] = normalizedGoVersion(module.Path, module.Version)
			}
		case message.OSV != nil:
			advisories[message.OSV.ID] = message.OSV
		case message.Finding != nil:
			finding := message.Finding
			if finding.OSV == "" || len(finding.Trace) != 1 {
				return nil, errors.New("govulncheck returned an invalid binary finding")
			}
			frame := finding.Trace[0]
			if frame.Function != "" {
				evidence.functionHits[finding.OSV] = true
			} else if frame.Package == "" {
				if evidence.moduleHits[finding.OSV] == nil {
					evidence.moduleHits[finding.OSV] = make(map[goModule]bool)
				}
				module := goModule{frame.Module, normalizedGoVersion(frame.Module, frame.Version)}
				evidence.moduleHits[finding.OSV][module] = true
			}
		}
	}
	if !gotConfig || len(evidence.modules) == 0 {
		return nil, errors.New("govulncheck returned incomplete binary analysis")
	}
	for _, advisory := range advisories {
		for _, id := range append([]string{advisory.ID}, advisory.Aliases...) {
			evidence.advisories[id] = append(evidence.advisories[id], advisory)
		}
	}
	return evidence, nil
}

func normalizedGoVersion(module, version string) string {
	if module == "stdlib" && strings.HasPrefix(version, "go") {
		return "v" + strings.TrimPrefix(version, "go")
	}
	return version
}

func (evidence *goBinaryEvidence) canOmit(vuln trivyVulnerability) bool {
	module := goModule{vuln.PkgName, normalizedGoVersion(vuln.PkgName, vuln.InstalledVersion)}
	if evidence == nil || !strings.HasPrefix(module.Version, "v") || evidence.modules[module.Path] != module.Version {
		return false
	}
	covered := false
	for _, advisory := range evidence.advisories[vuln.VulnerabilityID] {
		foundModule, hasImports, excludesPlatform := advisory.scope(module.Path, evidence.os, evidence.arch)
		if !foundModule {
			continue
		}
		if evidence.functionHits[advisory.ID] || !hasImports || (!excludesPlatform && !evidence.moduleHits[advisory.ID][module]) {
			return false
		}
		covered = true
	}
	return covered
}

// scope distinguishes explicit platform exclusions from incomplete coverage.
// An advisory without named packages gives no basis for a symbol-level omission.
func (advisory *goAdvisory) scope(module, os, arch string) (foundModule, hasImports, excludesPlatform bool) {
	excludesPlatform = os != "" && arch != ""
	for _, affected := range advisory.Affected {
		if affected.Package.Name != module {
			continue
		}
		foundModule = true
		imports := affected.EcosystemSpecific.Imports
		if len(imports) == 0 {
			return true, false, false
		}
		hasImports = true
		for _, pkg := range imports {
			if pkg.Path == "" {
				return true, false, false
			}
			osMatches := len(pkg.GOOS) == 0 || slices.Contains(pkg.GOOS, os)
			archMatches := len(pkg.GOARCH) == 0 || slices.Contains(pkg.GOARCH, arch)
			if osMatches && archMatches {
				excludesPlatform = false
			}
		}
	}
	return foundModule, hasImports, excludesPlatform
}
