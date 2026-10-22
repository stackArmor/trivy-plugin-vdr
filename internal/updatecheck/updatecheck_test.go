package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func noDebug(string, ...any) {}

func TestNewer(t *testing.T) {
	cases := []struct {
		candidate, current string
		want               bool
	}{
		{"4.12.0", "4.11.0", true},
		{"v4.11.1", "4.11.0", true},
		{"5.0.0", "4.99.99", true},
		{"4.11.0", "4.11.0", false},
		{"4.10.9", "4.11.0", false},
		{"4.11.0-rc.1", "4.11.0", false},
		{"4.12.0", "dev", false},
		{"garbage", "4.11.0", false},
	}
	for _, tc := range cases {
		if got := newer(tc.candidate, tc.current); got != tc.want {
			t.Errorf("newer(%q, %q) = %v, want %v", tc.candidate, tc.current, got, tc.want)
		}
	}
}

func TestStartReportsNewerRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "trivy-plugin-vdr/4.11.0" {
			t.Errorf("User-Agent = %q", got)
		}
		_, _ = w.Write([]byte(`{"tag_name":"v4.12.0","html_url":"https://example.test/releases/v4.12.0"}`))
	}))
	defer server.Close()

	result, ok := Start(context.Background(), server.URL, "4.11.0", noDebug)()
	if !ok {
		t.Fatal("lookup failed")
	}
	if !result.UpdateAvailable() || result.Latest != "4.12.0" || result.URL != "https://example.test/releases/v4.12.0" {
		t.Fatalf("result = %+v", result)
	}
}

func TestStartSkipsDevBuildsAndOptOut(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9"}`))
	}))
	defer server.Close()

	if _, ok := Start(context.Background(), server.URL, "dev", noDebug)(); ok {
		t.Fatal("dev build should skip the check")
	}
	t.Setenv(DisableEnv, "1")
	if _, ok := Start(context.Background(), server.URL, "4.11.0", noDebug)(); ok {
		t.Fatal("opt-out should skip the check")
	}
	if calls != 0 {
		t.Fatalf("server called %d times, want 0", calls)
	}
}

func TestStartFailureIsSilent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	var logged []string
	debug := func(format string, args ...any) { logged = append(logged, format) }
	if _, ok := Start(context.Background(), server.URL, "4.11.0", debug)(); ok {
		t.Fatal("a failed lookup should report ok=false")
	}
	if len(logged) != 1 {
		t.Fatalf("debug lines = %v, want one", logged)
	}
}
