package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type DiskSpace struct {
	FreeBytes  uint64
	TotalBytes uint64
}

type DiskSpaceProvider interface {
	DiskSpace(path string) (DiskSpace, error)
}

type ExistingPathResolver interface {
	NearestExistingPath(path string) (string, error)
}

type CacheCleanupOptions struct {
	Policy               CleanupPolicy
	Binary               string
	CacheDir             string
	MinFreeGB            int
	MinFreePercent       int
	CommandRunner        CommandRunner
	DiskSpaceProvider    DiskSpaceProvider
	ExistingPathResolver ExistingPathResolver
}

type trivyCacheCleaner struct {
	options CacheCleanupOptions
}

func NewCacheCleaner(options CacheCleanupOptions) CacheCleaner {
	return trivyCacheCleaner{options: options}
}

func (c trivyCacheCleaner) Cleanup(ctx context.Context) error {
	policy := c.options.Policy
	if policy == "" {
		policy = CleanupAuto
	}
	switch policy {
	case CleanupNever:
		return nil
	case CleanupAlways:
		return c.runClean(ctx)
	case CleanupAuto:
		needsCleanup, err := c.needsCleanup()
		if err != nil {
			return err
		}
		if !needsCleanup {
			return nil
		}
		return c.runClean(ctx)
	default:
		return fmt.Errorf("invalid cache cleanup policy %q", policy)
	}
}

func (c trivyCacheCleaner) needsCleanup() (bool, error) {
	cacheDir := c.options.CacheDir
	if cacheDir == "" {
		cacheDir = "."
	}

	resolver := c.options.ExistingPathResolver
	if resolver == nil {
		resolver = osExistingPathResolver{}
	}
	path, err := resolver.NearestExistingPath(cacheDir)
	if err != nil {
		return false, err
	}

	provider := c.options.DiskSpaceProvider
	if provider == nil {
		provider = statfsDiskSpaceProvider{}
	}
	space, err := provider.DiskSpace(path)
	if err != nil {
		return false, err
	}

	if c.options.MinFreeGB > 0 {
		minBytes := uint64(c.options.MinFreeGB) << 30
		if space.FreeBytes < minBytes {
			return true, nil
		}
	}
	if c.options.MinFreePercent > 0 && space.TotalBytes > 0 {
		freePercent := float64(space.FreeBytes) / float64(space.TotalBytes) * 100
		if freePercent < float64(c.options.MinFreePercent) {
			return true, nil
		}
	}
	return false, nil
}

func (c trivyCacheCleaner) runClean(ctx context.Context) error {
	binary := c.options.Binary
	if binary == "" {
		binary = defaultTrivyBinary
	}
	commandRunner := c.options.CommandRunner
	if commandRunner == nil {
		commandRunner = execCommandRunner{}
	}

	args := []string{"clean"}
	if c.options.CacheDir != "" {
		args = append(args, "--cache-dir", c.options.CacheDir)
	}
	args = append(args, "--scan-cache")

	_, stderr, err := commandRunner.Run(ctx, binary, args...)
	if err != nil {
		return fmt.Errorf("trivy clean --scan-cache failed: %w: %s", err, string(bytes.TrimSpace(stderr)))
	}
	return nil
}

type statfsDiskSpaceProvider struct{}

func (statfsDiskSpaceProvider) DiskSpace(path string) (DiskSpace, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return DiskSpace{}, err
	}
	return DiskSpace{
		FreeBytes:  uint64(stat.Bavail) * uint64(stat.Bsize),
		TotalBytes: uint64(stat.Blocks) * uint64(stat.Bsize),
	}, nil
}

type osExistingPathResolver struct{}

func (osExistingPathResolver) NearestExistingPath(path string) (string, error) {
	if path == "" {
		path = "."
	}
	current := filepath.Clean(path)
	for {
		if _, err := os.Stat(current); err == nil {
			return current, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing parent found for %q", path)
		}
		current = parent
	}
}
