package redis

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	limiter := NewRateLimiter(client, time.Minute)
	ctx := context.Background()

	tests := []struct {
		name    string
		key     string
		limit   int64
		wantErr bool
	}{
		{
			name:    "empty key",
			key:     "",
			limit:   10,
			wantErr: true,
		},
		{
			name:    "zero limit",
			key:     "test-key",
			limit:   0,
			wantErr: true,
		},
		{
			name:    "negative limit",
			key:     "test-key",
			limit:   -1,
			wantErr: true,
		},
		{
			name:    "valid request",
			key:     "test-key",
			limit:   10,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := limiter.Allow(ctx, tt.key, tt.limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("Allow() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("Allow() returned nil result for valid request")
			}
		})
	}
}

func TestRateLimiter_AllowSequence(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	limiter := NewRateLimiter(client, time.Minute)
	ctx := context.Background()

	key := "test-sequence"
	limit := int64(3)

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		result, err := limiter.Allow(ctx, key, limit)
		if err != nil {
			t.Fatalf("Allow() request %d error: %v", i+1, err)
		}
		if !result.Allowed {
			t.Errorf("Allow() request %d should be allowed", i+1)
		}
		if result.Count != int64(i+1) {
			t.Errorf("Allow() request %d count = %d, want %d", i+1, result.Count, i+1)
		}
		if result.Remaining != limit-int64(i+1) {
			t.Errorf("Allow() request %d remaining = %d, want %d", i+1, result.Remaining, limit-int64(i+1))
		}
	}

	// 4th request should be denied
	result, err := limiter.Allow(ctx, key, limit)
	if err != nil {
		t.Fatalf("Allow() 4th request error: %v", err)
	}
	if result.Allowed {
		t.Error("Allow() 4th request should be denied")
	}
	if result.Remaining != 0 {
		t.Errorf("Allow() 4th request remaining = %d, want 0", result.Remaining)
	}
	if result.RetryAfter <= 0 {
		t.Error("Allow() 4th request should have positive RetryAfter")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	limiter := NewRateLimiter(client, time.Minute)
	ctx := context.Background()

	key := "test-reset"
	limit := int64(1)

	// Use up the limit
	result, err := limiter.Allow(ctx, key, limit)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if !result.Allowed {
		t.Error("Allow() first request should be allowed")
	}

	// Second request should be denied
	result, err = limiter.Allow(ctx, key, limit)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if result.Allowed {
		t.Error("Allow() second request should be denied")
	}

	// Reset the limit
	err = limiter.Reset(ctx, key)
	if err != nil {
		t.Fatalf("Reset() error: %v", err)
	}

	// Request should now be allowed again
	result, err = limiter.Allow(ctx, key, limit)
	if err != nil {
		t.Fatalf("Allow() after reset error: %v", err)
	}
	if !result.Allowed {
		t.Error("Allow() after reset should be allowed")
	}
}

func TestRateLimiter_GetStatus(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	limiter := NewRateLimiter(client, time.Minute)
	ctx := context.Background()

	key := "test-status"
	limit := int64(5)

	// Make some requests
	for i := 0; i < 3; i++ {
		_, err := limiter.Allow(ctx, key, limit)
		if err != nil {
			t.Fatalf("Allow() request %d error: %v", i+1, err)
		}
	}

	// Check status
	status, err := limiter.GetStatus(ctx, key, limit)
	if err != nil {
		t.Fatalf("GetStatus() error: %v", err)
	}

	if status.Count != 3 {
		t.Errorf("GetStatus() count = %d, want 3", status.Count)
	}
	if status.Remaining != 2 {
		t.Errorf("GetStatus() remaining = %d, want 2", status.Remaining)
	}
	if !status.Allowed {
		t.Error("GetStatus() should show allowed = true")
	}
}

func TestAccountLockout_RecordFailedAttempt(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	lockout := NewAccountLockout(client)
	ctx := context.Background()

	key := "test-user"
	maxAttempts := 3
	lockoutDuration := time.Minute

	// First 2 attempts should not lock
	for i := 0; i < 2; i++ {
		result, err := lockout.RecordFailedAttempt(ctx, key, maxAttempts, lockoutDuration)
		if err != nil {
			t.Fatalf("RecordFailedAttempt() attempt %d error: %v", i+1, err)
		}
		if result.Blocked {
			t.Errorf("RecordFailedAttempt() attempt %d should not be blocked", i+1)
		}
		if result.Attempts != i+1 {
			t.Errorf("RecordFailedAttempt() attempt %d count = %d, want %d", i+1, result.Attempts, i+1)
		}
	}

	// 3rd attempt should lock
	result, err := lockout.RecordFailedAttempt(ctx, key, maxAttempts, lockoutDuration)
	if err != nil {
		t.Fatalf("RecordFailedAttempt() 3rd attempt error: %v", err)
	}
	if !result.Blocked {
		t.Error("RecordFailedAttempt() 3rd attempt should be blocked")
	}
	if result.Attempts != 3 {
		t.Errorf("RecordFailedAttempt() 3rd attempt count = %d, want 3", result.Attempts)
	}
	if result.Until.IsZero() {
		t.Error("RecordFailedAttempt() 3rd attempt should have Until time")
	}
}

func TestAccountLockout_IsBlocked(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	lockout := NewAccountLockout(client)
	ctx := context.Background()

	key := "test-user"

	// Initially not blocked
	result, err := lockout.IsBlocked(ctx, key)
	if err != nil {
		t.Fatalf("IsBlocked() error: %v", err)
	}
	if result.Blocked {
		t.Error("IsBlocked() should not be blocked initially")
	}

	// Lock the account
	maxAttempts := 1
	lockoutDuration := time.Hour
	_, err = lockout.RecordFailedAttempt(ctx, key, maxAttempts, lockoutDuration)
	if err != nil {
		t.Fatalf("RecordFailedAttempt() error: %v", err)
	}

	// Should now be blocked
	result, err = lockout.IsBlocked(ctx, key)
	if err != nil {
		t.Fatalf("IsBlocked() after lockout error: %v", err)
	}
	if !result.Blocked {
		t.Error("IsBlocked() should be blocked after lockout")
	}
	if result.Until.IsZero() {
		t.Error("IsBlocked() should have Until time")
	}
}

func TestAccountLockout_ClearFailedAttempts(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	lockout := NewAccountLockout(client)
	ctx := context.Background()

	key := "test-user"
	maxAttempts := 5
	lockoutDuration := time.Hour

	// Record some failed attempts
	for i := 0; i < 3; i++ {
		_, err := lockout.RecordFailedAttempt(ctx, key, maxAttempts, lockoutDuration)
		if err != nil {
			t.Fatalf("RecordFailedAttempt() attempt %d error: %v", i+1, err)
		}
	}

	// Clear attempts
	err := lockout.ClearFailedAttempts(ctx, key)
	if err != nil {
		t.Fatalf("ClearFailedAttempts() error: %v", err)
	}

	// Check that attempts are cleared
	result, err := lockout.IsBlocked(ctx, key)
	if err != nil {
		t.Fatalf("IsBlocked() after clear error: %v", err)
	}
	if result.Attempts != 0 {
		t.Errorf("IsBlocked() after clear attempts = %d, want 0", result.Attempts)
	}
	if result.Blocked {
		t.Error("IsBlocked() after clear should not be blocked")
	}
}

func TestAccountLockout_UnlockAccount(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	lockout := NewAccountLockout(client)
	ctx := context.Background()

	key := "test-user"
	maxAttempts := 1
	lockoutDuration := time.Hour

	// Lock the account
	_, err := lockout.RecordFailedAttempt(ctx, key, maxAttempts, lockoutDuration)
	if err != nil {
		t.Fatalf("RecordFailedAttempt() error: %v", err)
	}

	// Verify it's locked
	result, err := lockout.IsBlocked(ctx, key)
	if err != nil {
		t.Fatalf("IsBlocked() error: %v", err)
	}
	if !result.Blocked {
		t.Error("IsBlocked() should be blocked before unlock")
	}

	// Unlock the account
	err = lockout.UnlockAccount(ctx, key)
	if err != nil {
		t.Fatalf("UnlockAccount() error: %v", err)
	}

	// Verify it's unlocked
	result, err = lockout.IsBlocked(ctx, key)
	if err != nil {
		t.Fatalf("IsBlocked() after unlock error: %v", err)
	}
	if result.Blocked {
		t.Error("IsBlocked() after unlock should not be blocked")
	}
	if result.Attempts != 0 {
		t.Errorf("IsBlocked() after unlock attempts = %d, want 0", result.Attempts)
	}
}
