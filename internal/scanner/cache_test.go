package scanner

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCacheCleanerNeverSkipsCommand(t *testing.T) {
	runner := &recordingCommandRunner{}
	cleaner := NewCacheCleaner(CacheCleanupOptions{
		Policy:        CleanupNever,
		Binary:        "trivy-test",
		CommandRunner: runner,
	})

	if err := cleaner.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("command calls = %d, want 0", runner.calls)
	}
}

func TestCacheCleanerAlwaysRunsTrivyCleanScanCache(t *testing.T) {
	runner := &recordingCommandRunner{}
	cleaner := NewCacheCleaner(CacheCleanupOptions{
		Policy:        CleanupAlways,
		Binary:        "trivy-test",
		CommandRunner: runner,
	})

	if err := cleaner.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if runner.name != "trivy-test" {
		t.Fatalf("command name = %q, want trivy-test", runner.name)
	}
	wantArgs := []string{"clean", "--scan-cache"}
	if !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", runner.args, wantArgs)
	}
}

func TestCacheCleanerAutoRunsWhenFreeSpaceBelowThresholds(t *testing.T) {
	tests := []struct {
		name  string
		space DiskSpace
		want  int
	}{
		{name: "below GB", space: DiskSpace{FreeBytes: 9 << 30, TotalBytes: 200 << 30}, want: 1},
		{name: "below percent", space: DiskSpace{FreeBytes: 11 << 30, TotalBytes: 200 << 30}, want: 1},
		{name: "above both thresholds", space: DiskSpace{FreeBytes: 30 << 30, TotalBytes: 200 << 30}, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &recordingCommandRunner{}
			provider := &fakeDiskSpaceProvider{space: tt.space}
			cleaner := NewCacheCleaner(CacheCleanupOptions{
				Policy:               CleanupAuto,
				Binary:               "trivy-test",
				CacheDir:             filepath.Join("missing", "cache", "dir"),
				MinFreeGB:            10,
				MinFreePercent:       10,
				CommandRunner:        runner,
				DiskSpaceProvider:    provider,
				ExistingPathResolver: fakeExistingPathResolver{path: "missing"},
			})

			if err := cleaner.Cleanup(context.Background()); err != nil {
				t.Fatalf("Cleanup returned error: %v", err)
			}
			if runner.calls != tt.want {
				t.Fatalf("command calls = %d, want %d", runner.calls, tt.want)
			}
			if provider.path != "missing" {
				t.Fatalf("disk space path = %q, want nearest existing parent", provider.path)
			}
		})
	}
}

func TestCacheCleanerReturnsCommandFailureWithStderr(t *testing.T) {
	runner := &recordingCommandRunner{
		stderr: []byte("permission denied"),
		err:    errors.New("exit status 1"),
	}
	cleaner := NewCacheCleaner(CacheCleanupOptions{
		Policy:        CleanupAlways,
		CommandRunner: runner,
	})

	err := cleaner.Cleanup(context.Background())
	if err == nil {
		t.Fatal("Cleanup returned nil error, want command failure")
	}
	if got := err.Error(); got == "" || !containsAll(got, []string{"trivy clean", "permission denied"}) {
		t.Fatalf("error = %q, want cleanup failure context", got)
	}
}

type recordingCommandRunner struct {
	calls  int
	name   string
	args   []string
	stdout []byte
	stderr []byte
	err    error
}

func (r *recordingCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	r.calls++
	r.name = name
	r.args = append([]string(nil), args...)
	return r.stdout, r.stderr, r.err
}

type fakeDiskSpaceProvider struct {
	path  string
	space DiskSpace
	err   error
}

func (f *fakeDiskSpaceProvider) DiskSpace(path string) (DiskSpace, error) {
	f.path = path
	return f.space, f.err
}

type fakeExistingPathResolver struct {
	path string
	err  error
}

func (f fakeExistingPathResolver) NearestExistingPath(path string) (string, error) {
	return f.path, f.err
}

func containsAll(value string, parts []string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}
