//go:build integration
// +build integration

package redis

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// TestRedisIntegration tests the complete Redis functionality
func TestRedisIntegration(t *testing.T) {
	// Setup Redis client
	cfg := &config.RedisConfig{
		Host:         "localhost",
		Port:         6379,
		DB:           2, // Use different DB for integration tests
		PoolSize:     10,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Skipf("Redis not available for integration test: %v", err)
	}
	defer client.Close()

	// Clean test database
	ctx := context.Background()
	client.FlushDB(ctx)

	t.Run("SessionStore", func(t *testing.T) {
		testSessionStoreIntegration(t, client)
	})

	t.Run("RateLimiter", func(t *testing.T) {
		testRateLimiterIntegration(t, client)
	})

	t.Run("TokenBlacklist", func(t *testing.T) {
		testTokenBlacklistIntegration(t, client)
	})

	t.Run("AccountLockout", func(t *testing.T) {
		testAccountLockoutIntegration(t, client)
	})
}

func testSessionStoreIntegration(t *testing.T, client *Client) {
	store := NewSessionStore(client)
	ctx := context.Background()

	// Test session lifecycle
	sessionData := &SessionData{
		UserID:    "integration-user",
		Roles:     []string{"user", "admin"},
		IPAddress: "192.168.1.100",
		UserAgent: "integration-test-agent",
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	sessionID := "integration-session"

	// Store session
	err := store.Store(ctx, sessionID, sessionData, time.Minute)
	if err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	// Retrieve session
	retrieved, err := store.Get(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrieved.UserID != sessionData.UserID {
		t.Errorf("Session user ID mismatch: got %v, want %v", retrieved.UserID, sessionData.UserID)
	}

	// Update session
	sessionData.Roles = append(sessionData.Roles, "moderator")
	err = store.Update(ctx, sessionID, sessionData, time.Minute)
	if err != nil {
		t.Fatalf("Failed to update session: %v", err)
	}

	// Verify update
	updated, err := store.Get(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get updated session: %v", err)
	}

	if len(updated.Roles) != 3 {
		t.Errorf("Session roles not updated: got %d roles, want 3", len(updated.Roles))
	}

	// Test session expiration
	shortSession := "short-session"
	err = store.Store(ctx, shortSession, sessionData, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to store short session: %v", err)
	}

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	_, err = store.Get(ctx, shortSession)
	if err == nil {
		t.Error("Expected error for expired session")
	}

	// Clean up
	store.Delete(ctx, sessionID)
}

func testRateLimiterIntegration(t *testing.T, client *Client) {
	limiter := NewRateLimiter(client, time.Minute)
	ctx := context.Background()

	key := "integration-rate-limit"
	limit := int64(5)

	// Test rate limiting
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(ctx, key, limit)
		if err != nil {
			t.Fatalf("Allow() request %d error: %v", i+1, err)
		}
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	result, err := limiter.Allow(ctx, key, limit)
	if err != nil {
		t.Fatalf("Allow() 6th request error: %v", err)
	}
	if result.Allowed {
		t.Error("6th request should be denied")
	}

	// Test reset
	err = limiter.Reset(ctx, key)
	if err != nil {
		t.Fatalf("Reset() error: %v", err)
	}

	// Should be allowed again
	result, err = limiter.Allow(ctx, key, limit)
	if err != nil {
		t.Fatalf("Allow() after reset error: %v", err)
	}
	if !result.Allowed {
		t.Error("Request after reset should be allowed")
	}
}

func testTokenBlacklistIntegration(t *testing.T, client *Client) {
	blacklist := NewTokenBlacklist(client)
	ctx := context.Background()

	token := "integration-token-12345"
	userID := "integration-user"
	expiresAt := time.Now().Add(time.Hour)
	reason := "integration test"
	tokenType := "access"

	// Test blacklisting
	err := blacklist.BlacklistToken(ctx, token, userID, expiresAt, reason, tokenType)
	if err != nil {
		t.Fatalf("BlacklistToken() error: %v", err)
	}

	// Test checking blacklist
	isBlacklisted, blacklistedToken, err := blacklist.IsBlacklisted(ctx, token)
	if err != nil {
		t.Fatalf("IsBlacklisted() error: %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted")
	}
	if blacklistedToken.UserID != userID {
		t.Errorf("Blacklisted token user ID: got %v, want %v", blacklistedToken.UserID, userID)
	}

	// Test getting user tokens
	userTokens, err := blacklist.GetUserBlacklistedTokens(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserBlacklistedTokens() error: %v", err)
	}
	if len(userTokens) != 1 {
		t.Errorf("Expected 1 user token, got %d", len(userTokens))
	}

	// Test removal
	err = blacklist.RemoveToken(ctx, token)
	if err != nil {
		t.Fatalf("RemoveToken() error: %v", err)
	}

	isBlacklisted, _, err = blacklist.IsBlacklisted(ctx, token)
	if err != nil {
		t.Fatalf("IsBlacklisted() after removal error: %v", err)
	}
	if isBlacklisted {
		t.Error("Token should not be blacklisted after removal")
	}
}

func testAccountLockoutIntegration(t *testing.T, client *Client) {
	lockout := NewAccountLockout(client)
	ctx := context.Background()

	key := "integration-lockout-user"
	maxAttempts := 3
	lockoutDuration := time.Minute

	// Test failed attempts
	for i := 0; i < maxAttempts-1; i++ {
		result, err := lockout.RecordFailedAttempt(ctx, key, maxAttempts, lockoutDuration)
		if err != nil {
			t.Fatalf("RecordFailedAttempt() %d error: %v", i+1, err)
		}
		if result.Blocked {
			t.Errorf("Should not be blocked after %d attempts", i+1)
		}
	}

	// Final attempt should lock
	result, err := lockout.RecordFailedAttempt(ctx, key, maxAttempts, lockoutDuration)
	if err != nil {
		t.Fatalf("RecordFailedAttempt() final error: %v", err)
	}
	if !result.Blocked {
		t.Error("Should be blocked after max attempts")
	}

	// Verify lockout status
	blocked, err := lockout.IsBlocked(ctx, key)
	if err != nil {
		t.Fatalf("IsBlocked() error: %v", err)
	}
	if !blocked.Blocked {
		t.Error("Account should be blocked")
	}

	// Test unlock
	err = lockout.UnlockAccount(ctx, key)
	if err != nil {
		t.Fatalf("UnlockAccount() error: %v", err)
	}

	blocked, err = lockout.IsBlocked(ctx, key)
	if err != nil {
		t.Fatalf("IsBlocked() after unlock error: %v", err)
	}
	if blocked.Blocked {
		t.Error("Account should not be blocked after unlock")
	}
}

// TestRedisConnectionPooling tests connection pooling behavior
func TestRedisConnectionPooling(t *testing.T) {
	cfg := &config.RedisConfig{
		Host:         "localhost",
		Port:         6379,
		DB:           3,
		PoolSize:     5,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Skipf("Redis not available for connection pooling test: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test concurrent operations
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			key := fmt.Sprintf("pool-test-%d", id)
			value := fmt.Sprintf("value-%d", id)

			// Set value
			err := client.Set(ctx, key, value, time.Minute).Err()
			if err != nil {
				t.Errorf("Set error for key %s: %v", key, err)
				return
			}

			// Get value
			retrieved, err := client.Get(ctx, key).Result()
			if err != nil {
				t.Errorf("Get error for key %s: %v", key, err)
				return
			}

			if retrieved != value {
				t.Errorf("Value mismatch for key %s: got %v, want %v", key, retrieved, value)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check pool stats
	stats := client.GetStats()
	if stats.TotalConns == 0 {
		t.Error("Expected some connections in pool")
	}

	t.Logf("Pool stats: Total=%d, Idle=%d, Stale=%d",
		stats.TotalConns, stats.IdleConns, stats.StaleConns)
}
