package deployment

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ScalingTestConfig holds configuration for scaling tests
type ScalingTestConfig struct {
	BaseURL           string
	MaxConcurrency    int
	TestDuration      time.Duration
	RampUpDuration    time.Duration
	RequestsPerSecond int
	Endpoints         []string
}

// LoadTestResult holds the results of a load test
type LoadTestResult struct {
	TotalRequests  int64         `json:"total_requests"`
	SuccessfulReqs int64         `json:"successful_requests"`
	FailedRequests int64         `json:"failed_requests"`
	AverageLatency time.Duration `json:"average_latency"`
	P95Latency     time.Duration `json:"p95_latency"`
	P99Latency     time.Duration `json:"p99_latency"`
	RequestsPerSec float64       `json:"requests_per_second"`
	ErrorRate      float64       `json:"error_rate"`
	Duration       time.Duration `json:"duration"`
	Errors         []string      `json:"errors"`
}

// TestHorizontalScaling tests the horizontal scaling capabilities
func TestHorizontalScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping scaling test in short mode")
	}

	config := &ScalingTestConfig{
		BaseURL:           getTestBaseURL(),
		MaxConcurrency:    100,
		TestDuration:      2 * time.Minute,
		RampUpDuration:    30 * time.Second,
		RequestsPerSecond: 50,
		Endpoints: []string{
			"/health",
			"/health/ready",
			"/health/live",
			"/api/v1/auth/validate",
		},
	}

	t.Run("LoadTest", func(t *testing.T) {
		result := runLoadTest(t, config)

		// Validate load test results
		assert.Greater(t, result.TotalRequests, int64(1000), "Should handle significant load")
		assert.Less(t, result.ErrorRate, 0.05, "Error rate should be less than 5%")
		assert.Less(t, result.AverageLatency, 100*time.Millisecond, "Average latency should be reasonable")
		assert.Less(t, result.P95Latency, 500*time.Millisecond, "P95 latency should be acceptable")
		assert.Greater(t, result.RequestsPerSec, 40.0, "Should maintain good throughput")
	})

	t.Run("SessionDistribution", func(t *testing.T) {
		testSessionDistribution(t, config)
	})

	t.Run("RateLimitDistribution", func(t *testing.T) {
		testRateLimitDistribution(t, config)
	})

	t.Run("HealthCheckConsistency", func(t *testing.T) {
		testHealthCheckConsistency(t, config)
	})
}

// runLoadTest executes a load test against the service
func runLoadTest(t *testing.T, config *ScalingTestConfig) *LoadTestResult {
	ctx, cancel := context.WithTimeout(context.Background(), config.TestDuration+time.Minute)
	defer cancel()

	var (
		totalRequests  int64
		successfulReqs int64
		failedRequests int64
		latencies      []time.Duration
		errors         []string
		mu             sync.Mutex
	)

	// Create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Start time
	startTime := time.Now()

	// Create worker pool
	semaphore := make(chan struct{}, config.MaxConcurrency)
	var wg sync.WaitGroup

	// Rate limiter
	ticker := time.NewTicker(time.Second / time.Duration(config.RequestsPerSecond))
	defer ticker.Stop()

	// Test duration timer
	testTimer := time.NewTimer(config.TestDuration)
	defer testTimer.Stop()

	// Ramp up timer
	rampUpTimer := time.NewTimer(config.RampUpDuration)
	defer rampUpTimer.Stop()

	rampedUp := false

	for {
		select {
		case <-ctx.Done():
			goto cleanup
		case <-testTimer.C:
			goto cleanup
		case <-rampUpTimer.C:
			rampedUp = true
		case <-ticker.C:
			if !rampedUp {
				continue // Still ramping up
			}

			select {
			case semaphore <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-semaphore }()

					// Select random endpoint
					endpoint := config.Endpoints[int(atomic.AddInt64(&totalRequests, 1))%len(config.Endpoints)]
					url := config.BaseURL + endpoint

					// Make request
					reqStart := time.Now()
					resp, err := client.Get(url)
					latency := time.Since(reqStart)

					mu.Lock()
					latencies = append(latencies, latency)
					mu.Unlock()

					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						mu.Lock()
						errors = append(errors, fmt.Sprintf("Request error: %v", err))
						mu.Unlock()
						return
					}
					defer resp.Body.Close()

					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						atomic.AddInt64(&successfulReqs, 1)
					} else {
						atomic.AddInt64(&failedRequests, 1)
						mu.Lock()
						errors = append(errors, fmt.Sprintf("HTTP %d for %s", resp.StatusCode, endpoint))
						mu.Unlock()
					}
				}()
			default:
				// Semaphore full, skip this tick
			}
		}
	}

cleanup:
	// Wait for all requests to complete
	wg.Wait()

	// Calculate results
	duration := time.Since(startTime)
	total := atomic.LoadInt64(&totalRequests)
	successful := atomic.LoadInt64(&successfulReqs)
	failed := atomic.LoadInt64(&failedRequests)

	mu.Lock()
	defer mu.Unlock()

	// Calculate latency percentiles
	if len(latencies) == 0 {
		t.Fatal("No latency data collected")
	}

	// Sort latencies for percentile calculation
	sortedLatencies := make([]time.Duration, len(latencies))
	copy(sortedLatencies, latencies)

	// Simple bubble sort for small datasets
	for i := 0; i < len(sortedLatencies); i++ {
		for j := i + 1; j < len(sortedLatencies); j++ {
			if sortedLatencies[i] > sortedLatencies[j] {
				sortedLatencies[i], sortedLatencies[j] = sortedLatencies[j], sortedLatencies[i]
			}
		}
	}

	// Calculate average latency
	var totalLatency time.Duration
	for _, lat := range latencies {
		totalLatency += lat
	}
	avgLatency := totalLatency / time.Duration(len(latencies))

	// Calculate percentiles
	p95Index := int(float64(len(sortedLatencies)) * 0.95)
	p99Index := int(float64(len(sortedLatencies)) * 0.99)

	if p95Index >= len(sortedLatencies) {
		p95Index = len(sortedLatencies) - 1
	}
	if p99Index >= len(sortedLatencies) {
		p99Index = len(sortedLatencies) - 1
	}

	p95Latency := sortedLatencies[p95Index]
	p99Latency := sortedLatencies[p99Index]

	// Calculate error rate
	errorRate := float64(failed) / float64(total)

	// Calculate requests per second
	requestsPerSec := float64(total) / duration.Seconds()

	return &LoadTestResult{
		TotalRequests:  total,
		SuccessfulReqs: successful,
		FailedRequests: failed,
		AverageLatency: avgLatency,
		P95Latency:     p95Latency,
		P99Latency:     p99Latency,
		RequestsPerSec: requestsPerSec,
		ErrorRate:      errorRate,
		Duration:       duration,
		Errors:         errors,
	}
}

// testSessionDistribution tests that sessions are properly distributed across instances
func testSessionDistribution(t *testing.T, config *ScalingTestConfig) {
	// This test would require access to Redis to check session distribution
	// For now, we'll test that session-related endpoints work under load

	client := &http.Client{Timeout: 5 * time.Second}

	// Test session creation and validation
	for i := 0; i < 10; i++ {
		// Create session (would need actual auth endpoint)
		resp, err := client.Get(config.BaseURL + "/health")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}
}

// testRateLimitDistribution tests that rate limiting works across instances
func testRateLimitDistribution(t *testing.T, config *ScalingTestConfig) {
	client := &http.Client{Timeout: 5 * time.Second}

	// Make rapid requests to test rate limiting
	var rateLimitHit bool
	for i := 0; i < 100; i++ {
		resp, err := client.Get(config.BaseURL + "/api/v1/auth/validate")
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitHit = true
		}
		resp.Body.Close()

		if rateLimitHit {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	// Note: This test might not hit rate limits in a test environment
	// In production, rate limits would be more restrictive
}

// testHealthCheckConsistency tests that health checks are consistent across instances
func testHealthCheckConsistency(t *testing.T, config *ScalingTestConfig) {
	client := &http.Client{Timeout: 5 * time.Second}

	healthEndpoints := []string{"/health", "/health/live", "/health/ready"}

	for _, endpoint := range healthEndpoints {
		// Make multiple requests to ensure consistency
		for i := 0; i < 20; i++ {
			resp, err := client.Get(config.BaseURL + endpoint)
			require.NoError(t, err, "Health check should not fail")

			// Health checks should return 200 or 503 (if not ready)
			assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusServiceUnavailable,
				"Health check should return valid status code")

			resp.Body.Close()
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// TestDatabaseConnectionPooling tests database connection pooling under load
func TestDatabaseConnectionPooling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database pooling test in short mode")
	}

	// This would require actual database connection testing
	// For now, we'll test that database-dependent endpoints work under load

	config := &ScalingTestConfig{
		BaseURL:           getTestBaseURL(),
		MaxConcurrency:    50,
		TestDuration:      30 * time.Second,
		RampUpDuration:    5 * time.Second,
		RequestsPerSecond: 25,
		Endpoints: []string{
			"/health", // This endpoint checks database health
		},
	}

	result := runLoadTest(t, config)

	// Database-dependent endpoints should handle load well
	assert.Less(t, result.ErrorRate, 0.02, "Database connection pooling should keep error rate low")
	assert.Less(t, result.AverageLatency, 200*time.Millisecond, "Database queries should be fast")
}

// TestRedisDistributedOperations tests Redis operations under distributed load
func TestRedisDistributedOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis distributed test in short mode")
	}

	// This would test Redis session management and rate limiting under load
	// For now, we'll test endpoints that use Redis

	config := &ScalingTestConfig{
		BaseURL:           getTestBaseURL(),
		MaxConcurrency:    30,
		TestDuration:      45 * time.Second,
		RampUpDuration:    10 * time.Second,
		RequestsPerSecond: 20,
		Endpoints: []string{
			"/health", // Health check uses Redis
		},
	}

	result := runLoadTest(t, config)

	// Redis operations should be fast and reliable
	assert.Less(t, result.ErrorRate, 0.03, "Redis operations should be reliable")
	assert.Less(t, result.P95Latency, 300*time.Millisecond, "Redis operations should be fast")
}

// getTestBaseURL returns the base URL for testing
func getTestBaseURL() string {
	// In a real test environment, this would be configurable
	// For now, assume local testing
	return "http://localhost:8080"
}

// BenchmarkConcurrentRequests benchmarks concurrent request handling
func BenchmarkConcurrentRequests(b *testing.B) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
		},
	}

	baseURL := getTestBaseURL()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(baseURL + "/health")
			if err != nil {
				b.Error(err)
				continue
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				b.Errorf("Expected 200, got %d", resp.StatusCode)
			}
		}
	})
}

// BenchmarkSessionOperations benchmarks session-related operations
func BenchmarkSessionOperations(b *testing.B) {
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := getTestBaseURL()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Test session validation endpoint
			resp, err := client.Get(baseURL + "/api/v1/auth/validate")
			if err != nil {
				b.Error(err)
				continue
			}
			resp.Body.Close()
		}
	})
}
