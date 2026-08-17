package httpretry_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stackArmor/trivy-plugin-vdr/internal/httpretry"
)

type customTimeoutErr struct{}

func (e *customTimeoutErr) Error() string   { return "custom timeout" }
func (e *customTimeoutErr) Timeout() bool   { return true }
func (e *customTimeoutErr) Temporary() bool { return true }

func TestTransient(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			want: false,
		},
		{
			name: "context deadline exceeded",
			err:  context.DeadlineExceeded,
			want: false,
		},
		{
			name: "StatusError 502",
			err:  &httpretry.StatusError{StatusCode: 502},
			want: true,
		},
		{
			name: "StatusError 500",
			err:  &httpretry.StatusError{StatusCode: 500},
			want: true,
		},
		{
			name: "StatusError 503",
			err:  &httpretry.StatusError{StatusCode: 503},
			want: true,
		},
		{
			name: "StatusError 504",
			err:  &httpretry.StatusError{StatusCode: 504},
			want: true,
		},
		{
			name: "StatusError 429",
			err:  &httpretry.StatusError{StatusCode: 429},
			want: true,
		},
		{
			name: "StatusError 408",
			err:  &httpretry.StatusError{StatusCode: 408},
			want: true,
		},
		{
			name: "StatusError 425",
			err:  &httpretry.StatusError{StatusCode: 425},
			want: true,
		},
		{
			name: "StatusError 404",
			err:  &httpretry.StatusError{StatusCode: 404},
			want: false,
		},
		{
			name: "StatusError 403",
			err:  &httpretry.StatusError{StatusCode: 403},
			want: false,
		},
		{
			name: "StatusError 400",
			err:  &httpretry.StatusError{StatusCode: 400},
			want: false,
		},
		{
			name: "StatusError 501",
			err:  &httpretry.StatusError{StatusCode: 501},
			want: false,
		},
		{
			name: "wrapped StatusError 502",
			err:  errors.Join(errors.New("prefix"), &httpretry.StatusError{StatusCode: 502}),
			want: true,
		},
		{
			name: "io.ErrUnexpectedEOF",
			err:  io.ErrUnexpectedEOF,
			want: true,
		},
		{
			name: "io.EOF",
			err:  io.EOF,
			want: true,
		},
		{
			name: "net.Error timeout",
			err:  &customTimeoutErr{},
			want: true,
		},
		{
			name: "url.Error wrapping timeout",
			err:  &url.Error{Op: "Get", URL: "http://example.com", Err: &customTimeoutErr{}},
			want: true,
		},
		{
			name: "url.Error wrapping canceled context",
			err:  &url.Error{Op: "Get", URL: "http://example.com", Err: context.Canceled},
			want: false,
		},
		{
			name: "net.OpError",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection reset")},
			want: true,
		},
		{
			name: "generic permanent error",
			err:  errors.New("invalid json payload"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpretry.Transient(tt.err)
			if got != tt.want {
				t.Errorf("Transient(%v) = %v; want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestStatusErrorFormatting(t *testing.T) {
	err1 := &httpretry.StatusError{StatusCode: 502}
	if err1.Error() != "status 502" {
		t.Errorf("expected 'status 502', got '%s'", err1.Error())
	}

	err2 := &httpretry.StatusError{URL: "https://example.com", StatusCode: 502}
	if err2.Error() != "https://example.com: status 502" {
		t.Errorf("expected 'https://example.com: status 502', got '%s'", err2.Error())
	}
}

func TestDoRetriesUntilSuccess(t *testing.T) {
	attempts := 0
	delays := []time.Duration{0, 0}
	var warnedAttempts []int

	err := httpretry.Do(context.Background(), delays, func(attempt, total int, delay time.Duration, err error) {
		warnedAttempts = append(warnedAttempts, attempt)
	}, func() error {
		attempts++
		if attempts < 3 {
			return &httpretry.StatusError{StatusCode: 502}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
	if len(warnedAttempts) != 2 {
		t.Errorf("expected 2 warnings, got %d", len(warnedAttempts))
	}
}

func TestDoStopsOnPermanentError(t *testing.T) {
	attempts := 0
	delays := []time.Duration{0, 0}

	err := httpretry.Do(context.Background(), delays, nil, func() error {
		attempts++
		return &httpretry.StatusError{StatusCode: 403}
	})

	if err == nil {
		t.Fatalf("expected non-nil error")
	}
	if attempts != 1 {
		t.Errorf("expected exactly 1 attempt on permanent error, got %d", attempts)
	}
}

func TestDoExhaustsAndReturnsLastError(t *testing.T) {
	attempts := 0
	delays := []time.Duration{0, 0}

	expectedErr := &httpretry.StatusError{StatusCode: 502}
	err := httpretry.Do(context.Background(), delays, nil, func() error {
		attempts++
		return expectedErr
	})

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestDoRespectsContextCancellationDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	delays := []time.Duration{50 * time.Millisecond, 50 * time.Millisecond}
	attempts := 0

	err := httpretry.Do(ctx, delays, func(attempt, total int, delay time.Duration, err error) {
		// Cancel on first retry
		cancel()
	}, func() error {
		attempts++
		return &httpretry.StatusError{StatusCode: 502}
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt before cancel during delay, got %d", attempts)
	}
}

func TestWait(t *testing.T) {
	// Zero delay returns immediately with ctx.Err()
	if err := httpretry.Wait(context.Background(), 0); err != nil {
		t.Errorf("expected nil error on 0 delay, got %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := httpretry.Wait(canceledCtx, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on canceled ctx with 0 delay, got %v", err)
	}

	if err := httpretry.Wait(canceledCtx, 50*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on canceled ctx with positive delay, got %v", err)
	}
}
