// Package httpretry provides retry policy shared by the enrichment HTTP clients.
package httpretry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// DefaultDelays is the backoff schedule for enrichment fetches: 3 attempts total.
var DefaultDelays = []time.Duration{1 * time.Second, 3 * time.Second}

// StatusError reports a non-2xx HTTP response from an enrichment source.
type StatusError struct {
	URL        string
	StatusCode int
}

func (e *StatusError) Error() string {
	if e.URL != "" {
		return fmt.Sprintf("%s: status %d", e.URL, e.StatusCode)
	}
	return fmt.Sprintf("status %d", e.StatusCode)
}

// Transient reports whether err is worth retrying. Context errors are never
// transient: cancellation means the run is ending, not that the server is busy.
func Transient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case 408, 425, 429, 500, 502, 503, 504:
			return true
		default:
			return false
		}
	}

	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return true
		}
		if errors.Is(urlErr.Err, context.Canceled) || errors.Is(urlErr.Err, context.DeadlineExceeded) {
			return false
		}
		return Transient(urlErr.Err)
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	return false
}

// Wait sleeps for delay, returning early with ctx.Err() if ctx is done.
func Wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Do performs attempt with retries, logging each retry via warn if provided.
// It returns the final error when attempts are exhausted or err is permanent.
func Do(ctx context.Context, delays []time.Duration, warn func(attempt, total int, delay time.Duration, err error), attempt func() error) error {
	totalAttempts := len(delays) + 1
	var lastErr error

	for i := 0; i < totalAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := attempt()
		if err == nil {
			return nil
		}
		lastErr = err

		if !Transient(err) {
			return err
		}

		// If this was the last attempt, don't wait.
		if i == len(delays) {
			break
		}

		delay := delays[i]
		if warn != nil {
			warn(i+1, totalAttempts, delay, err)
		}

		if waitErr := Wait(ctx, delay); waitErr != nil {
			return waitErr
		}
	}

	return lastErr
}
