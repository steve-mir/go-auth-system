package redis

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DistributedRateLimiter implements distributed rate limiting across multiple instances
type DistributedRateLimiter struct {
	client     *Client
	instanceID string
	prefix     string
	windowSize time.Duration
	mu         sync.RWMutex

	// Metrics tracking
	totalRequests   int64
	allowedRequests int64
	blockedRequests int64
}

// DistributedRateLimitResult extends RateLimitResult with distributed information
type DistributedRateLimitResult struct {
	*RateLimitResult
	InstanceID      string           `json:"instance_id"`
	GlobalCount     int64            `json:"global_count"`
	InstanceCount   int64            `json:"instance_count"`
	ActiveInstances int              `json:"active_instances"`
	Distribution    map[string]int64 `json:"distribution"`
}

// InstanceMetrics holds rate limiting metrics for an instance
type InstanceMetrics struct {
	InstanceID  string    `json:"instance_id"`
	Requests    int64     `json:"requests"`
	Allowed     int64     `json:"allowed"`
	Blocked     int64     `json:"blocked"`
	LastUpdate  time.Time `json:"last_update"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}

// NewDistributedRateLimiter creates a new distributed rate limiter
func NewDistributedRateLimiter(client *Client, instanceID string, windowSize time.Duration) *DistributedRateLimiter {
	return &DistributedRateLimiter{
		client:     client,
		instanceID: instanceID,
		prefix:     "distributed_rate_limit:",
		windowSize: windowSize,
	}
}

// Allow checks if a request is allowed under the distributed rate limit
func (drl *DistributedRateLimiter) Allow(ctx context.Context, key string, globalLimit int64, instanceLimit int64) (*DistributedRateLimitResult, error) {
	if key == "" {
		return nil, fmt.Errorf("rate limit key cannot be empty")
	}
	if globalLimit <= 0 {
		return nil, fmt.Errorf("global rate limit must be positive")
	}

	now := time.Now()
	windowStart := now.Truncate(drl.windowSize)
	windowEnd := windowStart.Add(drl.windowSize)

	// Keys for distributed rate limiting
	globalKey := drl.prefix + "global:" + key
	instanceKey := drl.prefix + "instance:" + drl.instanceID + ":" + key
	distributionKey := drl.prefix + "distribution:" + key

	// Lua script for atomic distributed rate limiting
	luaScript := `
		local global_key = KEYS[1]
		local instance_key = KEYS[2]
		local distribution_key = KEYS[3]
		
		local window_start = tonumber(ARGV[1])
		local window_end = tonumber(ARGV[2])
		local global_limit = tonumber(ARGV[3])
		local instance_limit = tonumber(ARGV[4])
		local now = tonumber(ARGV[5])
		local instance_id = ARGV[6]
		
		-- Clean up expired entries
		redis.call('ZREMRANGEBYSCORE', global_key, 0, window_start - 1)
		redis.call('ZREMRANGEBYSCORE', instance_key, 0, window_start - 1)
		
		-- Get current counts
		local global_count = redis.call('ZCARD', global_key)
		local instance_count = redis.call('ZCARD', instance_key)
		
		-- Check global limit first
		if global_count >= global_limit then
			-- Update distribution tracking
			redis.call('HSET', distribution_key, instance_id, instance_count)
			redis.call('EXPIRE', distribution_key, math.ceil((window_end - now) / 1000))
			
			return {0, global_count, instance_count, window_end, 'global_limit_exceeded'}
		end
		
		-- Check instance limit if specified
		if instance_limit > 0 and instance_count >= instance_limit then
			-- Update distribution tracking
			redis.call('HSET', distribution_key, instance_id, instance_count)
			redis.call('EXPIRE', distribution_key, math.ceil((window_end - now) / 1000))
			
			return {0, global_count, instance_count, window_end, 'instance_limit_exceeded'}
		end
		
		-- Allow request - add to both global and instance counters
		redis.call('ZADD', global_key, now, instance_id .. ':' .. now)
		redis.call('ZADD', instance_key, now, now)
		
		-- Update distribution tracking
		redis.call('HSET', distribution_key, instance_id, instance_count + 1)
		
		-- Set expiration for cleanup
		redis.call('EXPIRE', global_key, math.ceil((window_end - now) / 1000))
		redis.call('EXPIRE', instance_key, math.ceil((window_end - now) / 1000))
		redis.call('EXPIRE', distribution_key, math.ceil((window_end - now) / 1000))
		
		return {1, global_count + 1, instance_count + 1, window_end, 'allowed'}
	`

	result, err := drl.client.Eval(ctx, luaScript,
		[]string{globalKey, instanceKey, distributionKey},
		windowStart.UnixMilli(),
		windowEnd.UnixMilli(),
		globalLimit,
		instanceLimit,
		now.UnixMilli(),
		drl.instanceID,
	).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to execute distributed rate limit check: %w", err)
	}

	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) != 5 {
		return nil, fmt.Errorf("unexpected distributed rate limit result format")
	}

	allowed := resultSlice[0].(int64) == 1
	globalCount := resultSlice[1].(int64)
	instanceCount := resultSlice[2].(int64)
	resetTime := time.UnixMilli(resultSlice[3].(int64))
	reason := resultSlice[4].(string)

	// Get distribution information
	distribution, err := drl.getDistribution(ctx, distributionKey)
	if err != nil {
		distribution = make(map[string]int64)
	}

	// Calculate remaining based on global limit
	remaining := globalLimit - globalCount
	if remaining < 0 {
		remaining = 0
	}

	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Until(resetTime)
	}

	// Update metrics
	drl.updateMetrics(allowed)

	// Create base rate limit result
	baseResult := &RateLimitResult{
		Allowed:     allowed,
		Count:       globalCount,
		Limit:       globalLimit,
		Remaining:   remaining,
		ResetTime:   resetTime,
		RetryAfter:  retryAfter,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
	}

	return &DistributedRateLimitResult{
		RateLimitResult: baseResult,
		InstanceID:      drl.instanceID,
		GlobalCount:     globalCount,
		InstanceCount:   instanceCount,
		ActiveInstances: len(distribution),
		Distribution:    distribution,
	}, nil
}

// getDistribution gets the current distribution of requests across instances
func (drl *DistributedRateLimiter) getDistribution(ctx context.Context, distributionKey string) (map[string]int64, error) {
	result, err := drl.client.HGetAll(ctx, distributionKey).Result()
	if err != nil {
		return nil, err
	}

	distribution := make(map[string]int64)
	for instanceID, countStr := range result {
		if count, err := strconv.ParseInt(countStr, 10, 64); err == nil {
			distribution[instanceID] = count
		}
	}

	return distribution, nil
}

// updateMetrics updates internal metrics
func (drl *DistributedRateLimiter) updateMetrics(allowed bool) {
	drl.mu.Lock()
	defer drl.mu.Unlock()

	drl.totalRequests++
	if allowed {
		drl.allowedRequests++
	} else {
		drl.blockedRequests++
	}
}

// GetMetrics returns current metrics for this instance
func (drl *DistributedRateLimiter) GetMetrics() *InstanceMetrics {
	drl.mu.RLock()
	defer drl.mu.RUnlock()

	now := time.Now()
	windowStart := now.Truncate(drl.windowSize)
	windowEnd := windowStart.Add(drl.windowSize)

	return &InstanceMetrics{
		InstanceID:  drl.instanceID,
		Requests:    drl.totalRequests,
		Allowed:     drl.allowedRequests,
		Blocked:     drl.blockedRequests,
		LastUpdate:  now,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
	}
}

// GetGlobalMetrics returns aggregated metrics across all instances
func (drl *DistributedRateLimiter) GetGlobalMetrics(ctx context.Context, key string) (map[string]*InstanceMetrics, error) {
	distributionKey := drl.prefix + "distribution:" + key

	distribution, err := drl.getDistribution(ctx, distributionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get distribution: %w", err)
	}

	metrics := make(map[string]*InstanceMetrics)
	now := time.Now()
	windowStart := now.Truncate(drl.windowSize)
	windowEnd := windowStart.Add(drl.windowSize)

	for instanceID, count := range distribution {
		metrics[instanceID] = &InstanceMetrics{
			InstanceID:  instanceID,
			Requests:    count,
			LastUpdate:  now,
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
		}
	}

	return metrics, nil
}

// Reset resets the distributed rate limit for a specific key
func (drl *DistributedRateLimiter) Reset(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("rate limit key cannot be empty")
	}

	globalKey := drl.prefix + "global:" + key
	instanceKey := drl.prefix + "instance:" + drl.instanceID + ":" + key
	distributionKey := drl.prefix + "distribution:" + key

	// Use pipeline for atomic reset
	pipe := drl.client.Pipeline()
	pipe.Del(ctx, globalKey)
	pipe.Del(ctx, instanceKey)
	pipe.Del(ctx, distributionKey)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to reset distributed rate limit: %w", err)
	}

	return nil
}

// GetStatus returns the current status of a distributed rate limit key
func (drl *DistributedRateLimiter) GetStatus(ctx context.Context, key string, globalLimit int64) (*DistributedRateLimitResult, error) {
	if key == "" {
		return nil, fmt.Errorf("rate limit key cannot be empty")
	}
	if globalLimit <= 0 {
		return nil, fmt.Errorf("global rate limit must be positive")
	}

	now := time.Now()
	windowStart := now.Truncate(drl.windowSize)
	windowEnd := windowStart.Add(drl.windowSize)

	globalKey := drl.prefix + "global:" + key
	instanceKey := drl.prefix + "instance:" + drl.instanceID + ":" + key
	distributionKey := drl.prefix + "distribution:" + key

	// Get current counts
	globalCount, err := drl.client.ZCount(ctx, globalKey,
		strconv.FormatInt(windowStart.UnixMilli(), 10),
		strconv.FormatInt(now.UnixMilli(), 10),
	).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get global count: %w", err)
	}

	instanceCount, err := drl.client.ZCount(ctx, instanceKey,
		strconv.FormatInt(windowStart.UnixMilli(), 10),
		strconv.FormatInt(now.UnixMilli(), 10),
	).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance count: %w", err)
	}

	// Get distribution
	distribution, err := drl.getDistribution(ctx, distributionKey)
	if err != nil {
		distribution = make(map[string]int64)
	}

	remaining := globalLimit - globalCount
	if remaining < 0 {
		remaining = 0
	}

	allowed := globalCount < globalLimit
	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Until(windowEnd)
	}

	baseResult := &RateLimitResult{
		Allowed:     allowed,
		Count:       globalCount,
		Limit:       globalLimit,
		Remaining:   remaining,
		ResetTime:   windowEnd,
		RetryAfter:  retryAfter,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
	}

	return &DistributedRateLimitResult{
		RateLimitResult: baseResult,
		InstanceID:      drl.instanceID,
		GlobalCount:     globalCount,
		InstanceCount:   instanceCount,
		ActiveInstances: len(distribution),
		Distribution:    distribution,
	}, nil
}

// CleanupExpired removes expired rate limit data
func (drl *DistributedRateLimiter) CleanupExpired(ctx context.Context) error {
	now := time.Now()
	windowStart := now.Truncate(drl.windowSize)

	// Get all rate limit keys
	pattern := drl.prefix + "*"
	keys, err := drl.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get rate limit keys: %w", err)
	}

	// Clean up expired entries
	for _, key := range keys {
		if err := drl.client.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart.UnixMilli()-1, 10)).Err(); err != nil {
			continue // Continue with other keys
		}
	}

	return nil
}

// GetActiveInstances returns a list of active instances for a key
func (drl *DistributedRateLimiter) GetActiveInstances(ctx context.Context, key string) ([]string, error) {
	distributionKey := drl.prefix + "distribution:" + key

	result, err := drl.client.HKeys(ctx, distributionKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to get active instances: %w", err)
	}

	return result, nil
}
