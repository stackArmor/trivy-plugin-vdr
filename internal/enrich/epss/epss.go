package epss

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/model"
)

const (
	DefaultURL   = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	cacheMaxAge  = 24 * time.Hour
	cacheSubdir  = "epss"
	cacheCSVName = "epss.csv"
)

type Store struct {
	cacheDir string
	url      string
	client   *http.Client
	now      func() time.Time

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

func NewStore(cacheDir string, options ...Option) *Store {
	store := &Store{
		cacheDir: cacheDir,
		url:      DefaultURL,
		client:   http.DefaultClient,
		now:      time.Now,
	}
	for _, option := range options {
		option(store)
	}
	if store.client == nil {
		store.client = http.DefaultClient
	}
	if store.now == nil {
		store.now = time.Now
	}
	return store
}

func (s *Store) Lookup(cveID string) (model.EPSS, bool, error) {
	if err := s.load(); err != nil {
		return model.EPSS{}, false, err
	}
	enrichment, ok := s.values[strings.ToUpper(cveID)]
	return enrichment, ok, nil
}

func EnrichFindings(findings []model.Finding, store *Store) ([]model.Finding, error) {
	enriched := append([]model.Finding(nil), findings...)
	if store == nil {
		return enriched, nil
	}
	for i := range enriched {
		epss, ok, err := store.Lookup(enriched[i].ID)
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

func (s *Store) load() error {
	if s.loaded {
		return nil
	}
	if err := s.refreshIfStale(); err != nil {
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

func (s *Store) refreshIfStale() error {
	info, err := os.Stat(s.cachePath())
	if err == nil && s.now().Sub(info.ModTime()) < cacheMaxAge {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return s.fetch()
}

func (s *Store) fetch() error {
	resp, err := s.client.Get(s.url)
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
	file, err := os.Create(s.cachePath())
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(file, reader); err != nil {
		return err
	}
	return nil
}

func (s *Store) cachePath() string {
	return filepath.Join(s.cacheDir, cacheSubdir, cacheCSVName)
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
