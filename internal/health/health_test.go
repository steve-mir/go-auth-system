package health

import (
	"context"
	"testing"
	"time"
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
