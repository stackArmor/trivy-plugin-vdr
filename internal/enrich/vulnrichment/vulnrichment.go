package vulnrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const DefaultBaseURL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"

const (
	cacheMaxAge = 7 * 24 * time.Hour
	httpTimeout = 30 * time.Second
)

var cvePattern = regexp.MustCompile(`^CVE-(\d{4})-(\d{4,})$`)

type Store struct {
	cacheDir     string
	baseURL      string
	client       *http.Client
	now          func() time.Time
	forceRefresh bool

	fetched atomic.Int64
	cached  atomic.Int64
}

// Stats reports how many CVE records were fetched over the network versus served
// from the local cache during the store's lifetime.
func (s *Store) Stats() (fetched, cached int) {
	return int(s.fetched.Load()), int(s.cached.Load())
}

type Option func(*Store)

func WithBaseURL(baseURL string) Option {
	return func(s *Store) {
		s.baseURL = strings.TrimRight(baseURL, "/")
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(s *Store) {
		s.client = client
	}
}

func WithNow(now func() time.Time) Option {
	return func(s *Store) {
		s.now = now
	}
}

func WithForceRefresh(forceRefresh bool) Option {
	return func(s *Store) {
		s.forceRefresh = forceRefresh
	}
}

func NewStore(cacheDir string, options ...Option) *Store {
	store := &Store{
		cacheDir: cacheDir,
		baseURL:  DefaultBaseURL,
		client:   &http.Client{Timeout: httpTimeout},
		now:      time.Now,
	}
	for _, option := range options {
		option(store)
	}
	store.client = normalizeClient(store.client)
	if store.now == nil {
		store.now = time.Now
	}
	return store
}

func normalizeClient(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Timeout: httpTimeout}
	}
	if client.Timeout != 0 {
		return client
	}
	copy := *client
	copy.Timeout = httpTimeout
	return &copy
}

func CacheRelativePath(cveID string) (string, error) {
	year, bucket, err := bucketForCVE(cveID)
	if err != nil {
		return "", err
	}
	return path.Join(year, bucket, strings.ToUpper(cveID)+".json"), nil
}

func (s *Store) Lookup(cveID string) (model.Vulnrichment, bool, error) {
	return s.LookupContext(context.Background(), cveID)
}

func (s *Store) LookupContext(ctx context.Context, cveID string) (model.Vulnrichment, bool, error) {
	data, sourceURL, ok, err := s.readOrFetch(ctx, cveID)
	if err != nil || !ok {
		return model.Vulnrichment{}, false, err
	}
	enrichment, ok, err := parse(data)
	if err != nil || !ok {
		return model.Vulnrichment{}, ok, err
	}
	enrichment.SourceURL = sourceURL
	return enrichment, true, nil
}

func EnrichFindings(findings []model.Finding, store *Store) ([]model.Finding, error) {
	return EnrichFindingsContext(context.Background(), findings, store)
}

func EnrichFindingsContext(ctx context.Context, findings []model.Finding, store *Store) ([]model.Finding, error) {
	enriched := append([]model.Finding(nil), findings...)
	if store == nil {
		return enriched, nil
	}
	for i := range enriched {
		vulnrichment, ok, err := store.LookupContext(ctx, enriched[i].ID)
		if err != nil {
			return nil, err
		}
		if ok {
			value := vulnrichment
			enriched[i].Vulnrichment = &value
			enriched[i].CWEs = append([]string(nil), value.CWEs...)
		}
	}
	return enriched, nil
}

func (s *Store) readOrFetch(ctx context.Context, cveID string) ([]byte, string, bool, error) {
	relativePath, err := CacheRelativePath(cveID)
	if err != nil {
		return nil, "", false, nil
	}
	cachePath := filepath.Join(s.cacheDir, "vulnrichment", filepath.FromSlash(relativePath))
	sourceURL := s.baseURL + "/" + relativePath

	data, err := os.ReadFile(cachePath)
	if err == nil {
		info, statErr := os.Stat(cachePath)
		if statErr != nil {
			return nil, "", false, statErr
		}
		if !s.forceRefresh && s.now().Sub(info.ModTime()) < cacheMaxAge {
			s.cached.Add(1)
			return data, sourceURL, true, nil
		}
		refreshedData, ok, fetchErr := s.fetch(ctx, cveID, cachePath, sourceURL)
		if fetchErr != nil {
			if json.Valid(data) {
				s.cached.Add(1)
				return data, sourceURL, true, nil
			}
			return nil, "", false, fetchErr
		}
		if !ok && json.Valid(data) {
			s.cached.Add(1)
			return data, sourceURL, true, nil
		}
		if ok {
			s.fetched.Add(1)
		}
		return refreshedData, sourceURL, ok, nil
	}
	if !os.IsNotExist(err) {
		return nil, "", false, err
	}

	data, ok, err := s.fetch(ctx, cveID, cachePath, sourceURL)
	if err != nil {
		return nil, "", false, err
	}
	if ok {
		s.fetched.Add(1)
	}
	return data, sourceURL, ok, nil
}

func (s *Store) fetch(ctx context.Context, cveID, cachePath, sourceURL string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetch Vulnrichment data for %s: %w", cveID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, false, fmt.Errorf("fetch Vulnrichment data for %s: status %d", cveID, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	if !json.Valid(data) {
		return nil, false, fmt.Errorf("parse Vulnrichment data for %s: invalid JSON", cveID)
	}
	if err := writeCacheFileAtomically(cachePath, data); err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func writeCacheFileAtomically(cachePath string, data []byte) error {
	cacheDir := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(cacheDir, "vulnrichment-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, cachePath); err != nil {
		return err
	}
	return nil
}

func bucketForCVE(cveID string) (string, string, error) {
	matches := cvePattern.FindStringSubmatch(strings.ToUpper(cveID))
	if matches == nil {
		return "", "", fmt.Errorf("invalid CVE ID %q", cveID)
	}
	number, err := strconv.Atoi(matches[2])
	if err != nil {
		return "", "", err
	}
	return matches[1], fmt.Sprintf("%dxxx", number/1000), nil
}

func parse(data []byte) (model.Vulnrichment, bool, error) {
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return model.Vulnrichment{}, false, err
	}
	root, ok := document.(map[string]any)
	if !ok {
		return model.Vulnrichment{}, false, nil
	}
	containers, _ := root["containers"].(map[string]any)

	var enrichment model.Vulnrichment
	if containers != nil {
		if adp, ok := containers["adp"].([]any); ok {
			walk(adp, func(object map[string]any) {
				other, ok := object["other"].(map[string]any)
				if !ok || !strings.EqualFold(stringValue(other["type"]), "ssvc") {
					return
				}
				content, ok := other["content"].(map[string]any)
				if !ok {
					return
				}
				options, ok := content["options"].([]any)
				if !ok {
					return
				}
				for _, option := range options {
					optionMap, ok := option.(map[string]any)
					if !ok {
						continue
					}
					for key, value := range optionMap {
						switch key {
						case "Exploitation":
							enrichment.Exploitation = stringValue(value)
						case "Automatable":
							enrichment.Automatable = stringValue(value)
						case "Technical Impact":
							enrichment.TechnicalImpact = stringValue(value)
						}
					}
				}
			})
		}
	}

	enrichment.CWEs = extractCWEs(root)

	if enrichment.Exploitation == "" && enrichment.Automatable == "" && enrichment.TechnicalImpact == "" && len(enrichment.CWEs) == 0 {
		return model.Vulnrichment{}, false, nil
	}
	return enrichment, true, nil
}

var cweIDPattern = regexp.MustCompile(`(?i)cwe-\d+`)

// normalizeCWE returns the canonical CWE identifier (e.g. "CWE-787") embedded in
// raw, or "" when none is present. The useless placeholders NVD-CWE-noinfo and
// NVD-CWE-Other are dropped (they lack a numeric ID, so the pattern rejects them;
// the explicit guard documents the intent).
func normalizeCWE(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "NVD-CWE-NOINFO", "NVD-CWE-OTHER":
		return ""
	}
	match := cweIDPattern.FindString(raw)
	if match == "" {
		return ""
	}
	return strings.ToUpper(match)
}

// extractCWEs resolves the CWE identifiers for a CVE record following the CC0
// source precedence: (1) CISA Vulnrichment ADP problemTypes, then (2) NVD
// CVE-record weaknesses[].description as a fallback. Order is preserved and
// duplicates removed; an empty slice means "no specific CWE" (fail-open).
func extractCWEs(root map[string]any) []string {
	var cwes []string
	seen := map[string]struct{}{}
	add := func(ids []string) {
		for _, id := range ids {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			cwes = append(cwes, id)
		}
	}

	// Tier 1: CISA Vulnrichment ADP CWE assignments.
	if containers, ok := root["containers"].(map[string]any); ok {
		if adp, ok := containers["adp"].([]any); ok {
			add(problemTypeCWEs(adp))
		}
	}
	if len(cwes) > 0 {
		return cwes
	}

	// Tier 2 (fallback): NVD CVE-record weaknesses[].description[].value. The
	// cisagov Vulnrichment feed consumed today does not carry this field, so this
	// tier stays dormant until an NVD source is wired into the enrich path.
	add(weaknessCWEs(root))
	return cwes
}

// problemTypeCWEs collects CWE ids from any problemTypes[].descriptions[] found
// under container, reading the structured cweId first and falling back to the
// free-text description when the entry is typed as a CWE.
func problemTypeCWEs(container any) []string {
	var out []string
	walk(container, func(object map[string]any) {
		problemTypes, ok := object["problemTypes"].([]any)
		if !ok {
			return
		}
		for _, pt := range problemTypes {
			ptMap, ok := pt.(map[string]any)
			if !ok {
				continue
			}
			descriptions, ok := ptMap["descriptions"].([]any)
			if !ok {
				continue
			}
			for _, description := range descriptions {
				descMap, ok := description.(map[string]any)
				if !ok {
					continue
				}
				if id := normalizeCWE(stringValue(descMap["cweId"])); id != "" {
					out = append(out, id)
					continue
				}
				if strings.EqualFold(stringValue(descMap["type"]), "CWE") {
					if id := normalizeCWE(stringValue(descMap["description"])); id != "" {
						out = append(out, id)
					}
				}
			}
		}
	})
	return out
}

// weaknessCWEs collects CWE ids from any NVD-shaped weaknesses[].description[]
// arrays found under root.
func weaknessCWEs(root any) []string {
	var out []string
	walk(root, func(object map[string]any) {
		weaknesses, ok := object["weaknesses"].([]any)
		if !ok {
			return
		}
		for _, weakness := range weaknesses {
			weaknessMap, ok := weakness.(map[string]any)
			if !ok {
				continue
			}
			descriptions, ok := weaknessMap["description"].([]any)
			if !ok {
				continue
			}
			for _, description := range descriptions {
				descMap, ok := description.(map[string]any)
				if !ok {
					continue
				}
				if id := normalizeCWE(stringValue(descMap["value"])); id != "" {
					out = append(out, id)
				}
			}
		}
	})
	return out
}

func walk(value any, visit func(map[string]any)) {
	switch typed := value.(type) {
	case map[string]any:
		visit(typed)
		for _, child := range typed {
			walk(child, visit)
		}
	case []any:
		for _, child := range typed {
			walk(child, visit)
		}
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}
