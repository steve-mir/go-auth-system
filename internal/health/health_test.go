package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLivenessChecker(t *testing.T) {
	checker := NewLivenessChecker()

	if checker.Name() != "liveness" {
		t.Errorf("Expected name 'liveness', got %s", checker.Name())
	}

	ctx := context.Background()
	health := checker.Check(ctx)

	if health.Status != StatusHealthy {
		t.Errorf("Expected status %s, got %s", StatusHealthy, health.Status)
	}

	if health.Message != "Application is alive" {
		t.Errorf("Expected message 'Application is alive', got %s", health.Message)
	}
}

func TestHealthService(t *testing.T) {
	service := NewService()

	// Add a liveness checker
	livenessChecker := NewLivenessChecker()
	service.AddChecker(livenessChecker)

	ctx := context.Background()
	response := service.Check(ctx)

	if response.Status != StatusHealthy {
		t.Errorf("Expected overall status %s, got %s", StatusHealthy, response.Status)
	}

	if len(response.Components) != 1 {
		t.Errorf("Expected 1 component, got %d", len(response.Components))
	}

	if _, exists := response.Components["liveness"]; !exists {
		t.Error("Expected liveness component to exist")
	}
}

func TestReadinessChecker(t *testing.T) {
	// Create a mock checker that's healthy
	healthyChecker := &mockChecker{
		name:   "test",
		status: StatusHealthy,
	}

	readinessChecker := NewReadinessChecker(healthyChecker)

	ctx := context.Background()
	health := readinessChecker.Check(ctx)

	if health.Status != StatusHealthy {
		t.Errorf("Expected status %s, got %s", StatusHealthy, health.Status)
	}
}

func TestReadinessCheckerWithUnhealthyComponent(t *testing.T) {
	// Create a mock checker that's unhealthy
	unhealthyChecker := &mockChecker{
		name:   "test",
		status: StatusUnhealthy,
	}

	readinessChecker := NewReadinessChecker(unhealthyChecker)

	ctx := context.Background()
	health := readinessChecker.Check(ctx)

	if health.Status != StatusUnhealthy {
		t.Errorf("Expected status %s, got %s", StatusUnhealthy, health.Status)
	}
}

// mockChecker is a mock implementation of the Checker interface for testing
type mockChecker struct {
	name   string
	status Status
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) Check(ctx context.Context) ComponentHealth {
	return ComponentHealth{
		Status:    m.status,
		Message:   "Mock checker",
		Timestamp: time.Now(),
		Duration:  time.Millisecond,
	}
}

// mockMonitoringService is a mock implementation of MonitoringService for testing
type mockMonitoringService struct {
	healthUpdates map[string]bool
}

func newMockMonitoringService() *mockMonitoringService {
	return &mockMonitoringService{
		healthUpdates: make(map[string]bool),
	}
}

func (m *mockMonitoringService) UpdateSystemHealth(component string, healthy bool) {
	m.healthUpdates[component] = healthy
}

func TestHealthServiceWithMonitoring(t *testing.T) {
	service := NewService()
	monitor := newMockMonitoringService()
	service.SetMonitoring(monitor)

	// Add checkers
	healthyChecker := &mockChecker{
		name:   "healthy_component",
		status: StatusHealthy,
	}
	unhealthyChecker := &mockChecker{
		name:   "unhealthy_component",
		status: StatusUnhealthy,
	}

	service.AddChecker(healthyChecker)
	service.AddChecker(unhealthyChecker)

	ctx := context.Background()
	response := service.Check(ctx)

	// Check that monitoring was called
	if !monitor.healthUpdates["healthy_component"] {
		t.Error("Expected healthy component to be reported as healthy")
	}

	if monitor.healthUpdates["unhealthy_component"] {
		t.Error("Expected unhealthy component to be reported as unhealthy")
	}

	if monitor.healthUpdates["overall"] {
		t.Error("Expected overall health to be unhealthy due to unhealthy component")
	}

	// Check overall status
	if response.Status != StatusUnhealthy {
		t.Errorf("Expected overall status %s, got %s", StatusUnhealthy, response.Status)
	}
}

func TestHealthServiceWithoutMonitoring(t *testing.T) {
	service := NewService()
	// Don't set monitoring service

	healthyChecker := &mockChecker{
		name:   "test",
		status: StatusHealthy,
	}
	service.AddChecker(healthyChecker)

	ctx := context.Background()
	response := service.Check(ctx)

	// Should not panic and should work normally
	if response.Status != StatusHealthy {
		t.Errorf("Expected status %s, got %s", StatusHealthy, response.Status)
	}
}

func TestHealthServiceDegradedStatus(t *testing.T) {
	service := NewService()
	monitor := newMockMonitoringService()
	service.SetMonitoring(monitor)

	// Add a degraded checker
	degradedChecker := &mockChecker{
		name:   "degraded_component",
		status: StatusDegraded,
	}
	service.AddChecker(degradedChecker)

	ctx := context.Background()
	response := service.Check(ctx)

	// Check overall status should be degraded
	if response.Status != StatusDegraded {
		t.Errorf("Expected overall status %s, got %s", StatusDegraded, response.Status)
	}

	// Overall health should still be reported as false for degraded
	if monitor.healthUpdates["overall"] {
		t.Error("Expected overall health to be false for degraded status")
	}
}

// mockRedisClient is a mock implementation for testing Redis health checker
type mockRedisClient struct {
	pingError bool
	infoError bool
}

func (m *mockRedisClient) Ping(ctx context.Context) *mockStatusCmd {
	return &mockStatusCmd{err: m.pingError}
}

func (m *mockRedisClient) Info(ctx context.Context, section ...string) *mockStringCmd {
	return &mockStringCmd{
		result: "# Memory\nused_memory:1000000\n",
		err:    m.infoError,
	}
}

type mockStatusCmd struct {
	err bool
}

func (m *mockStatusCmd) Err() error {
	if m.err {
		return assert.AnError
	}
	return nil
}

type mockStringCmd struct {
	result string
	err    bool
}

func (m *mockStringCmd) Result() (string, error) {
	if m.err {
		return "", assert.AnError
	}
	return m.result, nil
}

// Note: In a real implementation, you would need to properly mock the Redis client
// For now, we'll test the basic structure without the actual Redis dependency
func TestRedisCheckerStructure(t *testing.T) {
	// This test just verifies the structure exists
	// In a real test, you would use a mock Redis client

	// Test that we can create a Redis checker (even with nil client for structure test)
	checker := &RedisChecker{client: nil}

	if checker.Name() != "redis" {
		t.Errorf("Expected name 'redis', got %s", checker.Name())
	}

	// We can't test the actual Check method without a proper Redis mock
	// but we've verified the structure exists
}
