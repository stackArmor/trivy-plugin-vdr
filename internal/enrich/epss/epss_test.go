package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/model"
)

func TestLookupFetchesGunzipCachesAndParsesMetadata(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(gzipBytes(t, "# model_version:v2026.06.24,score_date:2026-06-24\ncve,epss,percentile\nCVE-2026-0001,0.42,0.93\n"))
	}))
	t.Cleanup(server.Close)

	cacheDir := t.TempDir()
	store := NewStore(cacheDir, WithURL(server.URL), WithHTTPClient(server.Client()), WithNow(func() time.Time { return now }))

	enrichment, ok, err := store.Lookup("CVE-2026-0001")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true")
	}
	if enrichment.Score != 0.42 || enrichment.Percentile != 0.93 {
		t.Fatalf("EPSS = score %v percentile %v, want 0.42 0.93", enrichment.Score, enrichment.Percentile)
	}
	if enrichment.ModelVersion != "v2026.06.24" {
		t.Fatalf("ModelVersion = %q, want v2026.06.24", enrichment.ModelVersion)
	}
	if enrichment.ScoreDate != "2026-06-24" {
		t.Fatalf("ScoreDate = %q, want 2026-06-24", enrichment.ScoreDate)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "epss", "epss.csv")); err != nil {
		t.Fatalf("cache file missing: %v", err)
	}
}

func TestNewStoreAppliesTimeoutToProvidedNoTimeoutClient(t *testing.T) {
	store := NewStore(t.TempDir(), WithHTTPClient(&http.Client{}))
	if store.client.Timeout == 0 {
		t.Fatal("client timeout = 0, want non-zero timeout")
	}
}

func TestLookupUsesFreshCacheWithoutRefresh(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	cachePath := filepath.Join(t.TempDir(), "epss", "epss.csv")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("# model_version:cached,score_date:2026-06-25\ncve,epss,percentile\nCVE-2026-0002,0.11,0.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cachePath, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called for fresh cache")
	}))
	t.Cleanup(server.Close)

	store := NewStore(filepath.Dir(filepath.Dir(cachePath)), WithURL(server.URL), WithHTTPClient(server.Client()), WithNow(func() time.Time { return now }))
	enrichment, ok, err := store.Lookup("CVE-2026-0002")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true")
	}
	if enrichment.Score != 0.11 || enrichment.Percentile != 0.22 || enrichment.ModelVersion != "cached" {
		t.Fatalf("enrichment = %+v, want cached EPSS values", enrichment)
	}
}

func TestLookupFailedRefreshLeavesStaleCacheUsable(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	cachePath := filepath.Join(t.TempDir(), "epss", "epss.csv")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	staleCSV := []byte("cve,epss,percentile\nCVE-2026-0009,0.33,0.44\n")
	if err := os.WriteFile(cachePath, staleCSV, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cachePath, now.Add(-48*time.Hour), now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("not gzip"))
	}))
	t.Cleanup(server.Close)

	store := NewStore(filepath.Dir(filepath.Dir(cachePath)), WithURL(server.URL), WithHTTPClient(server.Client()), WithNow(func() time.Time { return now }))
	enrichment, ok, err := store.Lookup("CVE-2026-0009")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true from stale cache")
	}
	if enrichment.Score != 0.33 {
		t.Fatalf("score = %v, want stale cache score 0.33", enrichment.Score)
	}
	got, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(staleCSV) {
		t.Fatalf("cache was modified after failed refresh: %q", string(got))
	}
}

func TestLookupEmptyRefreshLeavesStaleCacheUsable(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	cachePath := filepath.Join(t.TempDir(), "epss", "epss.csv")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	staleCSV := []byte("cve,epss,percentile\nCVE-2026-0011,0.55,0.66\n")
	if err := os.WriteFile(cachePath, staleCSV, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cachePath, now.Add(-48*time.Hour), now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(gzipBytes(t, "# model_version:empty,score_date:2026-06-25\n"))
	}))
	t.Cleanup(server.Close)

	store := NewStore(filepath.Dir(filepath.Dir(cachePath)), WithURL(server.URL), WithHTTPClient(server.Client()), WithNow(func() time.Time { return now }))
	enrichment, ok, err := store.Lookup("CVE-2026-0011")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true from stale cache")
	}
	if enrichment.Score != 0.55 {
		t.Fatalf("score = %v, want stale cache score 0.55", enrichment.Score)
	}
	got, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(staleCSV) {
		t.Fatalf("cache was modified after empty refresh: %q", string(got))
	}
}

func TestLookupContextCanceledReturnsErrorWithoutNetworkCall(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		t.Fatal("server should not be called with canceled context")
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, ok, err := NewStore(t.TempDir(), WithURL(server.URL), WithHTTPClient(server.Client())).LookupContext(ctx, "CVE-2026-0010")
	if err == nil {
		t.Fatal("LookupContext returned nil error, want context cancellation")
	}
	if ok {
		t.Fatal("LookupContext ok = true, want false")
	}
	if called {
		t.Fatal("server was called")
	}
}

func TestLookupMissingCVEReturnsNoEnrichment(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "epss", "epss.csv")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("cve,epss,percentile\nCVE-2026-0003,0.10,0.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(filepath.Dir(filepath.Dir(cachePath)))
	_, ok, err := store.Lookup("CVE-2026-9999")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if ok {
		t.Fatal("Lookup ok = true, want false")
	}
}

func TestEnrichFindingsPreservesFieldsAndAttachesEPSSByID(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "epss", "epss.csv")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("cve,epss,percentile\nCVE-2026-0004,0.70,0.99\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := []model.Finding{
		{ID: "CVE-2026-0004", ImageRef: "repo/app:1", Severity: "CRITICAL"},
		{ID: "CVE-2026-4040", ImageRef: "repo/app:1", Severity: "LOW"},
	}
	enriched, err := EnrichFindings(findings, NewStore(filepath.Dir(filepath.Dir(cachePath))))
	if err != nil {
		t.Fatalf("EnrichFindings returned error: %v", err)
	}
	if enriched[0].EPSS == nil {
		t.Fatal("first finding EPSS = nil, want enrichment")
	}
	if enriched[0].EPSS.Score != 0.70 {
		t.Fatalf("first finding score = %v, want 0.70", enriched[0].EPSS.Score)
	}
	if enriched[0].ImageRef != findings[0].ImageRef || enriched[0].Severity != findings[0].Severity {
		t.Fatalf("finding fields were not preserved: %+v", enriched[0])
	}
	if enriched[1].EPSS != nil {
		t.Fatalf("second finding EPSS = %+v, want nil", enriched[1].EPSS)
	}
}

func gzipBytes(t *testing.T, input string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
