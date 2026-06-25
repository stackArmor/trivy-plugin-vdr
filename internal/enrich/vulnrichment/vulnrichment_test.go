package vulnrichment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/model"
)

func TestBucketForCVE(t *testing.T) {
	tests := map[string]string{
		"CVE-2026-0001":   "2026/0xxx/CVE-2026-0001.json",
		"CVE-2026-9999":   "2026/9xxx/CVE-2026-9999.json",
		"CVE-2026-10000":  "2026/10xxx/CVE-2026-10000.json",
		"CVE-2026-25999":  "2026/25xxx/CVE-2026-25999.json",
		"CVE-2026-123456": "2026/123xxx/CVE-2026-123456.json",
		"CVE-2024-46446":  "2024/46xxx/CVE-2024-46446.json",
	}
	for cve, want := range tests {
		t.Run(cve, func(t *testing.T) {
			got, err := CacheRelativePath(cve)
			if err != nil {
				t.Fatalf("CacheRelativePath returned error: %v", err)
			}
			if got != want {
				t.Fatalf("CacheRelativePath = %q, want %q", got, want)
			}
		})
	}
}

func TestNewStoreAppliesTimeoutToProvidedNoTimeoutClient(t *testing.T) {
	store := NewStore(t.TempDir(), WithHTTPClient(&http.Client{}))
	if store.client.Timeout == 0 {
		t.Fatal("client timeout = 0, want non-zero timeout")
	}
}

func TestLookupFetchesCachesAndExtractsCISAADPSSVC(t *testing.T) {
	cacheDir := t.TempDir()
	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"containers": {
				"adp": [
					{
						"title": "CISA ADP Vulnrichment",
						"metrics": [
							{
								"other": {
									"type": "ssvc",
									"content": {
										"options": [
											{"Exploitation": "active"},
											{"Automatable": "yes"},
											{"Technical Impact": "total"}
										]
									}
								}
							}
						]
					}
				]
			}
		}`))
	}))
	t.Cleanup(server.Close)

	store := NewStore(cacheDir, WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	enrichment, ok, err := store.Lookup("CVE-2026-12345")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true")
	}
	if enrichment.Exploitation != "active" || enrichment.Automatable != "yes" || enrichment.TechnicalImpact != "total" {
		t.Fatalf("enrichment = %+v, want extracted SSVC values", enrichment)
	}
	if enrichment.SourceURL == "" {
		t.Fatal("SourceURL empty, want URL")
	}
	if requestedPath != "/2026/12xxx/CVE-2026-12345.json" {
		t.Fatalf("requested path = %q, want Vulnrichment raw path", requestedPath)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "vulnrichment", "2026", "12xxx", "CVE-2026-12345.json")); err != nil {
		t.Fatalf("cache file missing: %v", err)
	}
}

func TestLookupUsesFreshCacheWithoutRefresh(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "vulnrichment", "2026", "12xxx", "CVE-2026-12345.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, vulnrichmentJSON("cached"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cachePath, now.Add(-6*24*time.Hour), now.Add(-6*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called for fresh cache")
	}))
	t.Cleanup(server.Close)

	enrichment, ok, err := NewStore(cacheDir, WithBaseURL(server.URL), WithHTTPClient(server.Client()), WithNow(func() time.Time { return now })).Lookup("CVE-2026-12345")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true")
	}
	if enrichment.Exploitation != "cached" {
		t.Fatalf("Exploitation = %q, want cached", enrichment.Exploitation)
	}
}

func TestLookupRefreshesStaleCache(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "vulnrichment", "2026", "12xxx", "CVE-2026-12345.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, vulnrichmentJSON("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cachePath, now.Add(-8*24*time.Hour), now.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(vulnrichmentJSON("refreshed"))
	}))
	t.Cleanup(server.Close)

	enrichment, ok, err := NewStore(cacheDir, WithBaseURL(server.URL), WithHTTPClient(server.Client()), WithNow(func() time.Time { return now })).Lookup("CVE-2026-12345")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true")
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if enrichment.Exploitation != "refreshed" {
		t.Fatalf("Exploitation = %q, want refreshed", enrichment.Exploitation)
	}
}

func TestLookupForceRefreshFetchesEvenWhenCacheIsFresh(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "vulnrichment", "2026", "12xxx", "CVE-2026-12345.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, vulnrichmentJSON("cached"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cachePath, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(vulnrichmentJSON("forced"))
	}))
	t.Cleanup(server.Close)

	enrichment, ok, err := NewStore(cacheDir, WithBaseURL(server.URL), WithHTTPClient(server.Client()), WithNow(func() time.Time { return now }), WithForceRefresh(true)).Lookup("CVE-2026-12345")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true")
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if enrichment.Exploitation != "forced" {
		t.Fatalf("Exploitation = %q, want forced", enrichment.Exploitation)
	}
}

func TestLookupFailedForcedRefreshLeavesFreshCacheUsable(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "vulnrichment", "2026", "12xxx", "CVE-2026-12345.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	cachedJSON := vulnrichmentJSON("cached")
	if err := os.WriteFile(cachePath, cachedJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cachePath, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	enrichment, ok, err := NewStore(cacheDir, WithBaseURL(server.URL), WithHTTPClient(server.Client()), WithNow(func() time.Time { return now }), WithForceRefresh(true)).Lookup("CVE-2026-12345")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if !ok {
		t.Fatal("Lookup ok = false, want true from existing cache")
	}
	if enrichment.Exploitation != "cached" {
		t.Fatalf("Exploitation = %q, want cached", enrichment.Exploitation)
	}
	got, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(cachedJSON) {
		t.Fatalf("cache was modified after failed forced refresh: %q", string(got))
	}
}

func TestLookupDoesNotPublishInvalidFetchedJSON(t *testing.T) {
	cacheDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"containers":`))
	}))
	t.Cleanup(server.Close)

	store := NewStore(cacheDir, WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	_, ok, err := store.Lookup("CVE-2026-12345")
	if err == nil {
		t.Fatal("Lookup returned nil error, want invalid JSON error")
	}
	if ok {
		t.Fatal("Lookup ok = true, want false")
	}

	cachePath := filepath.Join(cacheDir, "vulnrichment", "2026", "12xxx", "CVE-2026-12345.json")
	if _, statErr := os.Stat(cachePath); !os.IsNotExist(statErr) {
		t.Fatalf("cache file stat error = %v, want file to not exist", statErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(filepath.Dir(cachePath), "vulnrichment-*.tmp"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}
}

func TestLookup404ReturnsNoEnrichmentWithoutError(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)

	store := NewStore(t.TempDir(), WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	_, ok, err := store.Lookup("CVE-2026-4040")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if ok {
		t.Fatal("Lookup ok = true, want false")
	}
}

func TestLookupMissingSSVCReturnsNoEnrichmentWithoutError(t *testing.T) {
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "vulnrichment", "2026", "0xxx", "CVE-2026-0005.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte(`{"containers":{"adp":[{"title":"CISA ADP Vulnrichment"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(cacheDir)
	_, ok, err := store.Lookup("CVE-2026-0005")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if ok {
		t.Fatal("Lookup ok = true, want false")
	}
}

func TestLookupNonCVEIDReturnsNoEnrichmentWithoutError(t *testing.T) {
	for _, id := range []string{"GHSA-xxxx", "ALAS2-foo"} {
		t.Run(id, func(t *testing.T) {
			store := NewStore(t.TempDir())
			_, ok, err := store.Lookup(id)
			if err != nil {
				t.Fatalf("Lookup returned error: %v", err)
			}
			if ok {
				t.Fatal("Lookup ok = true, want false")
			}
		})
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
	_, ok, err := NewStore(t.TempDir(), WithBaseURL(server.URL), WithHTTPClient(server.Client())).LookupContext(ctx, "CVE-2026-0008")
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

func TestLookupIgnoresNonADPSSVCData(t *testing.T) {
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "vulnrichment", "2026", "0xxx", "CVE-2026-0007.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte(`{
		"containers": {
			"cna": {
				"metrics": [{
					"other": {
						"type": "ssvc",
						"content": {
							"options": [
								{"Exploitation": "active"},
								{"Automatable": "yes"},
								{"Technical Impact": "total"}
							]
						}
					}
				}]
			}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, ok, err := NewStore(cacheDir).Lookup("CVE-2026-0007")
	if err != nil {
		t.Fatalf("Lookup returned error: %v", err)
	}
	if ok {
		t.Fatal("Lookup ok = true, want false")
	}
}

func TestEnrichFindingsIgnoresMissingCVEAndPreservesFields(t *testing.T) {
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "vulnrichment", "2026", "0xxx", "CVE-2026-0006.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte(`{
		"containers": {
			"adp": [{
				"metrics": [{
					"other": {
						"type": "ssvc",
						"content": {
							"options": [
								{"Exploitation": "poc"},
								{"Automatable": "no"},
								{"Technical Impact": "partial"}
							]
						}
					}
				}]
			}]
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)

	findings := []model.Finding{
		{ID: "CVE-2026-0006", ImageRef: "repo/app:1", Severity: "HIGH"},
		{ID: "CVE-2026-7777", ImageRef: "repo/app:1", Severity: "LOW"},
	}
	enriched, err := EnrichFindings(findings, NewStore(cacheDir, WithBaseURL(server.URL), WithHTTPClient(server.Client())))
	if err != nil {
		t.Fatalf("EnrichFindings returned error: %v", err)
	}
	if enriched[0].Vulnrichment == nil {
		t.Fatal("first finding Vulnrichment = nil, want enrichment")
	}
	if enriched[0].Vulnrichment.Exploitation != "poc" {
		t.Fatalf("Exploitation = %q, want poc", enriched[0].Vulnrichment.Exploitation)
	}
	if enriched[0].ImageRef != findings[0].ImageRef || enriched[0].Severity != findings[0].Severity {
		t.Fatalf("finding fields were not preserved: %+v", enriched[0])
	}
	if enriched[1].Vulnrichment != nil {
		t.Fatalf("second finding Vulnrichment = %+v, want nil", enriched[1].Vulnrichment)
	}
}

func TestEnrichFindingsSkipsNonCVEIDs(t *testing.T) {
	findings := []model.Finding{{ID: "GHSA-xxxx", ImageRef: "repo/app:1", Severity: "HIGH"}}
	enriched, err := EnrichFindings(findings, NewStore(t.TempDir()))
	if err != nil {
		t.Fatalf("EnrichFindings returned error: %v", err)
	}
	if enriched[0].Vulnrichment != nil {
		t.Fatalf("Vulnrichment = %+v, want nil", enriched[0].Vulnrichment)
	}
}

func vulnrichmentJSON(exploitation string) []byte {
	return []byte(`{
		"containers": {
			"adp": [{
				"metrics": [{
					"other": {
						"type": "ssvc",
						"content": {
							"options": [
								{"Exploitation": "` + exploitation + `"},
								{"Automatable": "yes"},
								{"Technical Impact": "total"}
							]
						}
					}
				}]
			}]
		}
	}`)
}
