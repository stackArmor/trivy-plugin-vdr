package controlcredit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// classPrefix marks a class reference in a row's cweClasses list.
const classPrefix = "class:"

// refPattern matches a pinned remote taxonomy reference: owner/repo@tag.
var refPattern = regexp.MustCompile(`^([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)@([A-Za-z0-9._/-]+)$`)

// changelogHeading matches a CHANGELOG version heading: "## 0.8.0 ...".
var changelogHeading = regexp.MustCompile(`(?m)^##\s+v?(\d+)\.(\d+)\.(\d+)`)

// filesToSkip in the taxonomy/ directory: classes are loaded separately and
// reachability-pointers is documentation the credit engine ignores.
var taxonomySkip = map[string]bool{
	"classes.yaml":               true,
	"reachability-pointers.yaml": true,
}

// Load resolves a --taxonomy ref and loads the control-credit taxonomy.
//
//   - An empty ref returns a disabled taxonomy (the default; engine inert), nil.
//   - A ref that is an existing local directory is loaded from disk.
//   - Otherwise the ref must be a pinned owner/repo@tag; the tarball is fetched
//     with the gh CLI (inheriting the operator's gh auth) and loaded. The tag
//     must be pinned: "latest" is rejected.
//
// On any resolution/parse/validation failure Load returns a non-nil error AND a
// disabled taxonomy marked StatusFailed, so the caller can log loudly and stamp
// the header without falling back to any other table.
func Load(ctx context.Context, ref string) (*Taxonomy, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Disabled(), nil
	}

	if info, err := os.Stat(ref); err == nil && info.IsDir() {
		tax, err := loadFromDir(ref)
		if err != nil {
			return failed(ref), err
		}
		tax.Ref = ref
		if tax.Version == "" {
			tax.Version = changelogVersion(ref)
		}
		return tax, nil
	}

	owner, repo, tag, ok := parseRemoteRef(ref)
	if !ok {
		return failed(ref), fmt.Errorf("taxonomy ref %q is neither an existing directory nor owner/repo@tag", ref)
	}
	if isUnpinned(tag) {
		return failed(ref), fmt.Errorf("taxonomy ref %q uses an unpinned tag %q; pin to a release tag or digest", ref, tag)
	}

	dir, cleanup, err := fetchViaGH(ctx, owner, repo, tag)
	if err != nil {
		return failed(ref), err
	}
	defer cleanup()

	tax, err := loadFromDir(dir)
	if err != nil {
		return failed(ref), err
	}
	tax.Ref = ref
	// The pinned tag is authoritative for reproducibility.
	tax.Version = strings.TrimPrefix(tag, "v")
	return tax, nil
}

// parseRemoteRef splits owner/repo@tag.
func parseRemoteRef(ref string) (owner, repo, tag string, ok bool) {
	m := refPattern.FindStringSubmatch(ref)
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

// isUnpinned rejects moving refs; a taxonomy release must be pinned so a score
// is reproducible against a named release.
func isUnpinned(tag string) bool {
	switch strings.ToLower(tag) {
	case "latest", "main", "master", "head":
		return true
	default:
		return false
	}
}

// fetchViaGH downloads the repo tarball at the pinned tag via the gh CLI as a
// child process (no in-process token handling; it inherits the operator's gh
// auth), extracts it to a temp dir, and returns that dir plus a cleanup func.
func fetchViaGH(ctx context.Context, owner, repo, tag string) (string, func(), error) {
	if _, err := exec.LookPath("gh"); err != nil {
		return "", func() {}, fmt.Errorf("gh CLI not found on PATH; required to fetch private taxonomy %s/%s@%s: %w", owner, repo, tag, err)
	}

	apiPath := fmt.Sprintf("repos/%s/%s/tarball/%s", owner, repo, tag)
	cmd := exec.CommandContext(ctx, "gh", "api", apiPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", func() {}, fmt.Errorf("gh api %s failed: %w: %s", apiPath, err, strings.TrimSpace(stderr.String()))
	}

	dir, err := os.MkdirTemp("", "vdr-taxonomy-")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temp dir for taxonomy: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := extractTarball(bytes.NewReader(stdout.Bytes()), dir); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("extract taxonomy tarball for %s/%s@%s: %w", owner, repo, tag, err)
	}
	return dir, cleanup, nil
}

// extractTarball reads a gzipped tarball and writes its files under dest,
// stripping the single leading path component GitHub adds
// (owner-repo-<sha>/...). Path traversal entries are rejected.
func extractTarball(r io.Reader, dest string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		rel := stripLeadingComponent(hdr.Name)
		if rel == "" {
			continue
		}
		if !isSafeRelPath(rel) {
			return fmt.Errorf("unsafe path in tarball: %q", hdr.Name)
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil { //nolint:gosec // taxonomy tarball from operator's gh auth
				f.Close()
				return err
			}
			f.Close()
		default:
			// skip symlinks and other special entries
		}
	}
	return nil
}

func stripLeadingComponent(name string) string {
	name = path.Clean("/" + name)
	name = strings.TrimPrefix(name, "/")
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

func isSafeRelPath(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") {
		return false
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// loadFromDir loads rows, classes, and verification sources from a taxonomy
// root directory, expands class references, and validates the result.
func loadFromDir(root string) (*Taxonomy, error) {
	classes, err := loadClasses(filepath.Join(root, "taxonomy", "classes.yaml"))
	if err != nil {
		return nil, err
	}

	rows, err := loadRows(filepath.Join(root, "taxonomy"))
	if err != nil {
		return nil, err
	}

	sources, err := loadVerificationSources(filepath.Join(root, "profiles", "verification-sources.yaml"))
	if err != nil {
		return nil, err
	}

	if err := expandRows(rows, classes); err != nil {
		return nil, err
	}
	if err := validate(rows); err != nil {
		return nil, err
	}

	return &Taxonomy{
		Enabled:             true,
		Status:              StatusLoaded,
		Tier:                tierForRows(rows),
		Rows:                rows,
		Classes:             classes,
		VerificationSources: sources,
	}, nil
}

func loadClasses(pth string) (map[string]Class, error) {
	data, err := os.ReadFile(pth)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Class{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", pth, err)
	}
	var doc struct {
		Classes map[string]Class `yaml:"classes"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", pth, err)
	}
	if doc.Classes == nil {
		doc.Classes = map[string]Class{}
	}
	return doc.Classes, nil
}

func loadRows(taxonomyDir string) ([]Row, error) {
	entries, err := os.ReadDir(taxonomyDir)
	if err != nil {
		return nil, fmt.Errorf("read taxonomy dir %s: %w", taxonomyDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".yaml" || taxonomySkip[name] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names) // deterministic row order across platforms

	var rows []Row
	for _, name := range names {
		pth := filepath.Join(taxonomyDir, name)
		data, err := os.ReadFile(pth)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", pth, err)
		}
		var doc struct {
			Rows []Row `yaml:"rows"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", pth, err)
		}
		rows = append(rows, doc.Rows...)
	}
	return rows, nil
}

func loadVerificationSources(pth string) (map[string]VerificationSource, error) {
	data, err := os.ReadFile(pth)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]VerificationSource{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", pth, err)
	}
	var doc struct {
		Controls map[string]VerificationSource `yaml:"controls"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", pth, err)
	}
	if doc.Controls == nil {
		doc.Controls = map[string]VerificationSource{}
	}
	return doc.Controls, nil
}

// expandRows resolves each row's cweClasses into unconditional and
// availability-only CWE sets, expanding any class references at load time.
func expandRows(rows []Row, classes map[string]Class) error {
	for i := range rows {
		var uncond, availOnly []string
		for _, entry := range rows[i].Counters.CWEClasses {
			if !strings.HasPrefix(entry, classPrefix) {
				uncond = append(uncond, entry)
				continue
			}
			name := strings.TrimPrefix(entry, classPrefix)
			class, ok := classes[name]
			if !ok {
				return fmt.Errorf("row %q references unknown class %q", rows[i].ID, entry)
			}
			uncond = append(uncond, class.Members...)
			availOnly = append(availOnly, class.MembersWhenAvailabilityOnly...)
		}
		rows[i].expandedCWEs = dedupe(uncond)
		rows[i].availabilityOnlyCWEs = dedupe(availOnly)
	}
	return nil
}

// validate is the CC1 schema check: every row needs an id and a credit lane.
func validate(rows []Row) error {
	seen := map[string]bool{}
	for _, r := range rows {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("taxonomy row missing id (title %q)", r.Title)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate taxonomy row id %q", r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Credit.Lane) == "" {
			return fmt.Errorf("taxonomy row %q missing credit.lane", r.ID)
		}
	}
	return nil
}

// tierForRows labels the loaded table. A non-empty table whose every row is
// marked visibility: public is the public snippet; anything else is the full
// private table.
func tierForRows(rows []Row) string {
	if len(rows) == 0 {
		return TierFull
	}
	for _, r := range rows {
		if r.Visibility != "public" {
			return TierFull
		}
	}
	return TierSnippet
}

// changelogVersion reads the highest semantic version from the taxonomy's
// CHANGELOG.md. It scans all headings and picks the max, so it is robust to
// either changelog ordering (newest-first or oldest-first).
func changelogVersion(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		return ""
	}
	matches := changelogHeading.FindAllStringSubmatch(string(data), -1)
	var best [3]int
	var found bool
	for _, m := range matches {
		v := [3]int{atoi(m[1]), atoi(m[2]), atoi(m[3])}
		if !found || less(best, v) {
			best = v
			found = true
		}
	}
	if !found {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", best[0], best[1], best[2])
}

func less(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
