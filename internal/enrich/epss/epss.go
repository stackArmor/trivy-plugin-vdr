package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/model"
)

const (
	DefaultURL   = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	cacheMaxAge  = 24 * time.Hour
	cacheSubdir  = "epss"
	cacheCSVName = "epss.csv"
	httpTimeout  = 30 * time.Second
)

type Store struct {
	cacheDir     string
	url          string
	client       *http.Client
	now          func() time.Time
	forceRefresh bool

	loaded bool
	values map[string]model.EPSS
}

type Option func(*Store)

func WithURL(url string) Option {
	return func(s *Store) {
		s.url = url
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
		url:      DefaultURL,
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

func (s *Store) Lookup(cveID string) (model.EPSS, bool, error) {
	return s.LookupContext(context.Background(), cveID)
}

func (s *Store) LookupContext(ctx context.Context, cveID string) (model.EPSS, bool, error) {
	if err := s.load(ctx); err != nil {
		return model.EPSS{}, false, err
	}
	enrichment, ok := s.values[strings.ToUpper(cveID)]
	return enrichment, ok, nil
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
		epss, ok, err := store.LookupContext(ctx, enriched[i].ID)
		if err != nil {
			return nil, err
		}
		if ok {
			value := epss
			enriched[i].EPSS = &value
		}
	}
	return enriched, nil
}

func (s *Store) load(ctx context.Context) error {
	if s.loaded {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.refreshIfStale(ctx); err != nil && !cacheExists(s.cachePath()) {
		return err
	}

	file, err := os.Open(s.cachePath())
	if err != nil {
		return err
	}
	defer file.Close()

	values, err := parseCSV(file)
	if err != nil {
		return err
	}
	s.values = values
	s.loaded = true
	return nil
}

func (s *Store) refreshIfStale(ctx context.Context) error {
	info, err := os.Stat(s.cachePath())
	if err == nil && !s.forceRefresh && s.now().Sub(info.ModTime()) < cacheMaxAge {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return s.fetch(ctx)
}

func (s *Store) fetch(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch EPSS data: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("fetch EPSS data: status %d", resp.StatusCode)
	}

	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gunzip EPSS data: %w", err)
	}
	defer reader.Close()

	if err := os.MkdirAll(filepath.Dir(s.cachePath()), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(s.cachePath()), "epss-*.csv")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if _, err := io.Copy(file, reader); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	tempFile, err := os.Open(tempPath)
	if err != nil {
		return err
	}
	values, err := parseCSV(tempFile)
	if err != nil {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	if len(values) == 0 {
		return fmt.Errorf("parse EPSS CSV: no score rows found")
	}
	return os.Rename(tempPath, s.cachePath())
}

func (s *Store) cachePath() string {
	return filepath.Join(s.cacheDir, cacheSubdir, cacheCSVName)
}

func cacheExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func parseCSV(reader io.Reader) (map[string]model.EPSS, error) {
	scanner := bufio.NewScanner(reader)
	var csvLines []string
	metadata := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			parseMetadataLine(metadata, line)
			continue
		}
		if strings.TrimSpace(line) != "" {
			csvLines = append(csvLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	csvReader := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return map[string]model.EPSS{}, nil
	}

	header := map[string]int{}
	for i, column := range records[0] {
		header[strings.ToLower(strings.TrimSpace(column))] = i
	}
	cveIndex, hasCVE := header["cve"]
	scoreIndex, hasScore := header["epss"]
	percentileIndex, hasPercentile := header["percentile"]
	if !hasCVE || !hasScore || !hasPercentile {
		return nil, fmt.Errorf("parse EPSS CSV: missing required header")
	}

	values := make(map[string]model.EPSS, len(records)-1)
	for _, record := range records[1:] {
		if len(record) <= cveIndex || len(record) <= scoreIndex || len(record) <= percentileIndex {
			continue
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(record[scoreIndex]), 64)
		if err != nil {
			return nil, err
		}
		percentile, err := strconv.ParseFloat(strings.TrimSpace(record[percentileIndex]), 64)
		if err != nil {
			return nil, err
		}
		cveID := strings.ToUpper(strings.TrimSpace(record[cveIndex]))
		if cveID == "" {
			continue
		}
		values[cveID] = model.EPSS{
			Score:        score,
			Percentile:   percentile,
			ModelVersion: metadata["model_version"],
			ScoreDate:    metadata["score_date"],
		}
	}
	return values, nil
}

func parseMetadataLine(metadata map[string]string, line string) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ';'
	})
	for _, field := range fields {
		key, value, ok := strings.Cut(field, ":")
		if !ok {
			key, value, ok = strings.Cut(field, "=")
		}
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		key = strings.ReplaceAll(key, " ", "_")
		metadata[key] = strings.TrimSpace(value)
	}
}
