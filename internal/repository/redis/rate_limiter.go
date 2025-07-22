package redis

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed     bool          `json:"allowed"`
	Count       int64         `json:"count"`
	Limit       int64         `json:"limit"`
	Remaining   int64         `json:"remaining"`
	ResetTime   time.Time     `json:"reset_time"`
	RetryAfter  time.Duration `json:"retry_after"`
	WindowStart time.Time     `json:"window_start"`
	WindowEnd   time.Time     `json:"window_end"`
}

// RateLimiter implements sliding window rate limiting using Redis
type RateLimiter struct {
	client     *Client
	prefix     string
	windowSize time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(client *Client, windowSize time.Duration) *RateLimiter {
	return &RateLimiter{
		client:     client,
		prefix:     "rate_limit:",
		windowSize: windowSize,
	}
}

// Allow checks if a request is allowed under the rate limit
func (rl *RateLimiter) Allow(ctx context.Context, key string, limit int64) (*RateLimitResult, error) {
	if key == "" {
		return nil, fmt.Errorf("rate limit key cannot be empty")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("rate limit must be positive")
	}

	now := time.Now()
	windowStart := now.Truncate(rl.windowSize)
	windowEnd := windowStart.Add(rl.windowSize)

	redisKey := rl.prefix + key

	// Use Lua script for atomic operations
	luaScript := `
		local key = KEYS[1]
		local window_start = tonumber(ARGV[1])
		local window_end = tonumber(ARGV[2])
		local limit = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])
		
		-- Remove expired entries
		redis.call('ZREMRANGEBYSCORE', key, 0, window_start - 1)
		
		-- Count current requests in window
		local count = redis.call('ZCARD', key)
		
		-- Check if limit exceeded
		if count >= limit then
			-- Set expiration for cleanup
			redis.call('EXPIRE', key, math.ceil((window_end - now) / 1000))
			return {0, count, window_end}
		end
		
		-- Add current request
		redis.call('ZADD', key, now, now)
		
		-- Set expiration for cleanup
		redis.call('EXPIRE', key, math.ceil((window_end - now) / 1000))
		
		return {1, count + 1, window_end}
	`

	result, err := rl.client.Eval(ctx, luaScript, []string{redisKey},
		windowStart.UnixMilli(),
		windowEnd.UnixMilli(),
		limit,
		now.UnixMilli(),
	).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to execute rate limit check: %w", err)
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 3 {
		return nil, fmt.Errorf("unexpected rate limit result format")
	}

	allowed := resultSlice[0].(int64) == 1
	count := resultSlice[1].(int64)
	resetTime := time.UnixMilli(resultSlice[2].(int64))

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Until(resetTime)
	}

	return &RateLimitResult{
		Allowed:     allowed,
		Count:       count,
		Limit:       limit,
		Remaining:   remaining,
		ResetTime:   resetTime,
		RetryAfter:  retryAfter,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
	}, nil
}

// Reset resets the rate limit for a specific key
func (rl *RateLimiter) Reset(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("rate limit key cannot be empty")
	}

	redisKey := rl.prefix + key
	if err := rl.client.Del(ctx, redisKey).Err(); err != nil {
		return fmt.Errorf("failed to reset rate limit: %w", err)
	}

	return nil
}

// GetStatus returns the current status of a rate limit key
func (rl *RateLimiter) GetStatus(ctx context.Context, key string, limit int64) (*RateLimitResult, error) {
	if key == "" {
		return nil, fmt.Errorf("rate limit key cannot be empty")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("rate limit must be positive")
	}

	now := time.Now()
	windowStart := now.Truncate(rl.windowSize)
	windowEnd := windowStart.Add(rl.windowSize)

	redisKey := rl.prefix + key

	// Count current requests in window
	count, err := rl.client.ZCount(ctx, redisKey,
		strconv.FormatInt(windowStart.UnixMilli(), 10),
		strconv.FormatInt(now.UnixMilli(), 10),
	).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit status: %w", err)
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	allowed := count < limit
	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Until(windowEnd)
	}

	return &RateLimitResult{
		Allowed:     allowed,
		Count:       count,
		Limit:       limit,
		Remaining:   remaining,
		ResetTime:   windowEnd,
		RetryAfter:  retryAfter,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
	}, nil
}

// BlockedUntil returns when a key will be unblocked (for account lockouts)
type BlockedUntil struct {
	Blocked  bool      `json:"blocked"`
	Until    time.Time `json:"until,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Attempts int       `json:"attempts"`
}

// AccountLockout handles progressive account lockout functionality
type AccountLockout struct {
	client *Client
	prefix string
}

// NewAccountLockout creates a new account lockout manager
func NewAccountLockout(client *Client) *AccountLockout {
	return &AccountLockout{
		client: client,
		prefix: "lockout:",
	}
}

// RecordFailedAttempt records a failed login attempt
func (al *AccountLockout) RecordFailedAttempt(ctx context.Context, key string, maxAttempts int, lockoutDuration time.Duration) (*BlockedUntil, error) {
	if key == "" {
		return nil, fmt.Errorf("lockout key cannot be empty")
	}

	redisKey := al.prefix + key
	attemptsKey := redisKey + ":attempts"
	blockedKey := redisKey + ":blocked"

	// Increment failed attempts
	attempts, err := al.client.Incr(ctx, attemptsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to increment failed attempts: %w", err)
	}

	// Set expiration for attempts counter (24 hours)
	al.client.Expire(ctx, attemptsKey, 24*time.Hour)

	// Check if account should be locked
	if int(attempts) >= maxAttempts {
		// Lock the account
		until := time.Now().Add(lockoutDuration)
		if err := al.client.Set(ctx, blockedKey, until.Unix(), lockoutDuration).Err(); err != nil {
			return nil, fmt.Errorf("failed to lock account: %w", err)
		}

		return &BlockedUntil{
			Blocked:  true,
			Until:    until,
			Reason:   "too many failed attempts",
			Attempts: int(attempts),
		}, nil
	}

	return &BlockedUntil{
		Blocked:  false,
		Attempts: int(attempts),
	}, nil
}

// IsBlocked checks if an account is currently blocked
func (al *AccountLockout) IsBlocked(ctx context.Context, key string) (*BlockedUntil, error) {
	if key == "" {
		return nil, fmt.Errorf("lockout key cannot be empty")
	}

	redisKey := al.prefix + key
	attemptsKey := redisKey + ":attempts"
	blockedKey := redisKey + ":blocked"

	// Check if blocked
	blockedUntil, err := al.client.Get(ctx, blockedKey).Result()
	if err != nil {
		if err == redis.Nil {
			// Not blocked, get attempt count
			attempts, err := al.client.Get(ctx, attemptsKey).Result()
			if err != nil {
				if err == redis.Nil {
					return &BlockedUntil{Blocked: false, Attempts: 0}, nil
				}
				return nil, fmt.Errorf("failed to get attempts count: %w", err)
			}

			attemptsInt, _ := strconv.Atoi(attempts)
			return &BlockedUntil{Blocked: false, Attempts: attemptsInt}, nil
		}
		return nil, fmt.Errorf("failed to check if blocked: %w", err)
	}

	// Parse blocked until time
	blockedUntilInt, err := strconv.ParseInt(blockedUntil, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse blocked until time: %w", err)
	}

	until := time.Unix(blockedUntilInt, 0)
	if time.Now().After(until) {
		// Lockout has expired, clean up
		al.client.Del(ctx, blockedKey)
		return &BlockedUntil{Blocked: false}, nil
	}

	// Get attempt count
	attempts, _ := al.client.Get(ctx, attemptsKey).Result()
	attemptsInt, _ := strconv.Atoi(attempts)

	return &BlockedUntil{
		Blocked:  true,
		Until:    until,
		Reason:   "account locked due to failed attempts",
		Attempts: attemptsInt,
	}, nil
}

// ClearFailedAttempts clears failed attempts for a key (after successful login)
func (al *AccountLockout) ClearFailedAttempts(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("lockout key cannot be empty")
	}

	redisKey := al.prefix + key
	attemptsKey := redisKey + ":attempts"
	blockedKey := redisKey + ":blocked"

	// Clear both attempts and blocked status
	if err := al.client.Del(ctx, attemptsKey, blockedKey).Err(); err != nil {
		return fmt.Errorf("failed to clear failed attempts: %w", err)
	}

	return nil
}

// UnlockAccount manually unlocks an account
func (al *AccountLockout) UnlockAccount(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("lockout key cannot be empty")
	}

	redisKey := al.prefix + key
	attemptsKey := redisKey + ":attempts"
	blockedKey := redisKey + ":blocked"

	// Remove lockout and reset attempts
	if err := al.client.Del(ctx, attemptsKey, blockedKey).Err(); err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	return nil
}
