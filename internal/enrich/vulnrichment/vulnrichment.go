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
	"time"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/model"
)

const DefaultBaseURL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"

const httpTimeout = 30 * time.Second

var cvePattern = regexp.MustCompile(`^CVE-(\d{4})-(\d{4,})$`)

type Store struct {
	cacheDir string
	baseURL  string
	client   *http.Client
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

func NewStore(cacheDir string, options ...Option) *Store {
	store := &Store{
		cacheDir: cacheDir,
		baseURL:  DefaultBaseURL,
		client:   &http.Client{Timeout: httpTimeout},
	}
	for _, option := range options {
		option(store)
	}
	store.client = normalizeClient(store.client)
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
		return data, sourceURL, true, nil
	}
	if !os.IsNotExist(err) {
		return nil, "", false, err
	}

	if err := ctx.Err(); err != nil {
		return nil, "", false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, "", false, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch Vulnrichment data for %s: %w", cveID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, sourceURL, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "", false, fmt.Errorf("fetch Vulnrichment data for %s: status %d", cveID, resp.StatusCode)
	}
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, err
	}
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return nil, "", false, err
	}
	if err := os.WriteFile(cachePath, data, 0o644); err != nil {
		return nil, "", false, err
	}
	return data, sourceURL, true, nil
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
	containers, ok := root["containers"].(map[string]any)
	if !ok {
		return model.Vulnrichment{}, false, nil
	}
	adp, ok := containers["adp"].([]any)
	if !ok {
		return model.Vulnrichment{}, false, nil
	}

	var enrichment model.Vulnrichment
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

	if enrichment.Exploitation == "" && enrichment.Automatable == "" && enrichment.TechnicalImpact == "" {
		return model.Vulnrichment{}, false, nil
	}
	return enrichment, true, nil
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
