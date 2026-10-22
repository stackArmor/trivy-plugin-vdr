// Package updatecheck looks up the latest published plugin release so a run can
// tell the operator an upgrade is available. It is advisory only: any failure
// (offline, rate limited, blocked egress) is silent apart from a debug line, and
// the check never delays or fails a scan.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultURL is the GitHub API endpoint for the plugin's latest release.
const DefaultURL = "https://api.github.com/repos/stackArmor/trivy-plugin-vdr/releases/latest"

// DisableEnv turns the check off when set to any non-empty value other than
// "0" or "false", for air-gapped or egress-restricted runners.
const DisableEnv = "VDR_NO_UPDATE_CHECK"

// Timeout bounds the lookup; a run never waits longer than this for it.
const Timeout = 3 * time.Second

const maxResponseBytes = 64 << 10

// Result is a completed lookup.
type Result struct {
	Current string
	Latest  string
	URL     string
}

// UpdateAvailable reports whether Latest is a newer release than Current.
func (r Result) UpdateAvailable() bool {
	return newer(r.Latest, r.Current)
}

// Disabled reports whether the environment opts out of the check.
func Disabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(DisableEnv)))
	return value != "" && value != "0" && value != "false"
}

// Latest fetches the latest release tag from url. current is the running
// version as embedded by the release build (without a leading "v").
func Latest(ctx context.Context, client *http.Client, url, current string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "trivy-plugin-vdr/"+current)
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("latest release lookup returned HTTP %d", resp.StatusCode)
	}
	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&release); err != nil {
		return Result{}, fmt.Errorf("decode latest release: %w", err)
	}
	if strings.TrimSpace(release.TagName) == "" {
		return Result{}, fmt.Errorf("latest release has no tag")
	}
	return Result{Current: current, Latest: strings.TrimPrefix(strings.TrimSpace(release.TagName), "v"), URL: release.HTMLURL}, nil
}

// Start runs the lookup in the background and returns a function that waits
// for it, at most until the lookup's own timeout, and returns the result. The
// returned function yields ok=false when the check was skipped or failed.
func Start(ctx context.Context, url, current string, debug func(format string, args ...any)) func() (Result, bool) {
	if !comparable(current) || Disabled() {
		return func() (Result, bool) { return Result{}, false }
	}
	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		lookupCtx, cancel := context.WithTimeout(ctx, Timeout)
		defer cancel()
		result, err := Latest(lookupCtx, &http.Client{Timeout: Timeout}, url, current)
		done <- outcome{result, err}
	}()
	// The lookup is bounded by Timeout, so waiting on it is too.
	return func() (Result, bool) {
		got := <-done
		if got.err != nil {
			debug("plugin update check skipped: %v", got.err)
			return Result{}, false
		}
		return got.result, true
	}
}

// comparable reports whether version is a release version the check can order.
// Development builds ("dev") and unparsable values skip the check.
func comparable(version string) bool {
	_, ok := parse(version)
	return ok
}

func newer(candidate, current string) bool {
	a, okA := parse(candidate)
	b, okB := parse(current)
	if !okA || !okB {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// parse reads MAJOR.MINOR.PATCH, ignoring a leading "v" and any pre-release or
// build suffix. A pre-release of the latest version therefore never prompts an
// upgrade to that same version.
func parse(version string) ([3]int, bool) {
	var parts [3]int
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if i := strings.IndexAny(version, "-+"); i >= 0 {
		version = version[:i]
	}
	fields := strings.Split(version, ".")
	if len(fields) != 3 {
		return parts, false
	}
	for i, field := range fields {
		n, err := strconv.Atoi(field)
		if err != nil || n < 0 {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}
