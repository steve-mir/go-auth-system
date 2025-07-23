package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// Status represents the health status of a component
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
)

// ComponentHealth represents the health of a single component
type ComponentHealth struct {
	Status    Status        `json:"status"`
	Message   string        `json:"message,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration_ms"`
}

// HealthResponse represents the overall health response
type HealthResponse struct {
	Status     Status                     `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Components map[string]ComponentHealth `json:"components"`
}

// Checker defines the interface for health checkers
type Checker interface {
	Check(ctx context.Context) ComponentHealth
	Name() string
}

// Service manages health checks for the application
type Service struct {
	checkers []Checker
	monitor  MonitoringService
}

// MonitoringService interface for health check monitoring
type MonitoringService interface {
	UpdateSystemHealth(component string, healthy bool)
}

// NewService creates a new health service
func NewService() *Service {
	return &Service{
		checkers: make([]Checker, 0),
	}
}

// SetMonitoring sets the monitoring service for health checks
func (s *Service) SetMonitoring(monitor MonitoringService) {
	s.monitor = monitor
}

// AddChecker adds a health checker to the service
func (s *Service) AddChecker(checker Checker) {
	s.checkers = append(s.checkers, checker)
}

// Check performs all health checks and returns the overall status
func (s *Service) Check(ctx context.Context) HealthResponse {
	start := time.Now()
	components := make(map[string]ComponentHealth)
	overallStatus := StatusHealthy

	// Run all health checks
	for _, checker := range s.checkers {
		health := checker.Check(ctx)
		components[checker.Name()] = health

		// Update monitoring metrics if available
		if s.monitor != nil {
			healthy := health.Status == StatusHealthy
			s.monitor.UpdateSystemHealth(checker.Name(), healthy)
		}

		// Determine overall status
		if health.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
		} else if health.Status == StatusDegraded && overallStatus == StatusHealthy {
			overallStatus = StatusDegraded
		}
	}

	// Update overall system health
	if s.monitor != nil {
		s.monitor.UpdateSystemHealth("overall", overallStatus == StatusHealthy)
	}

	return HealthResponse{
		Status:     overallStatus,
		Timestamp:  start,
		Components: components,
	}
}

// Handler returns an HTTP handler for health checks
func (s *Service) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		health := s.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		// Set appropriate HTTP status code
		switch health.Status {
		case StatusHealthy:
			w.WriteHeader(http.StatusOK)
		case StatusDegraded:
			w.WriteHeader(http.StatusOK) // Still return 200 for degraded
		case StatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		if err := json.NewEncoder(w).Encode(health); err != nil {
			http.Error(w, "Failed to encode health response", http.StatusInternalServerError)
		}
	}
}

// LivenessHandler returns a simple liveness probe handler for Kubernetes
func (s *Service) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Simple liveness check - if we can respond, we're alive
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"status":    "alive",
			"timestamp": time.Now(),
		}

		json.NewEncoder(w).Encode(response)
	}
}

// ReadinessHandler returns a readiness probe handler for Kubernetes
func (s *Service) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Check critical dependencies for readiness
		health := s.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		// For readiness, we need all critical components to be healthy
		ready := true
		criticalComponents := []string{"database", "redis"}

		for _, component := range criticalComponents {
			if componentHealth, exists := health.Components[component]; exists {
				if componentHealth.Status == StatusUnhealthy {
					ready = false
					break
				}
			}
		}

		if ready {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		response := map[string]interface{}{
			"status":     map[bool]string{true: "ready", false: "not_ready"}[ready],
			"timestamp":  time.Now(),
			"components": health.Components,
		}

		json.NewEncoder(w).Encode(response)
	}
}

// DatabaseChecker implements health checking for PostgreSQL database
type DatabaseChecker struct {
	db *postgres.DB
}

// NewDatabaseChecker creates a new database health checker
func NewDatabaseChecker(db *postgres.DB) *DatabaseChecker {
	return &DatabaseChecker{db: db}
}

// Name returns the name of this health checker
func (c *DatabaseChecker) Name() string {
	return "database"
}

// Check performs the database health check
func (c *DatabaseChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Check database connection
	if err := c.db.Health(ctx); err != nil {
		return ComponentHealth{
			Status:    StatusUnhealthy,
			Message:   fmt.Sprintf("Database connection failed: %v", err),
			Timestamp: start,
			Duration:  time.Since(start),
		}
	}

	// Get connection pool stats
	stats := c.db.Stats()

	// Check if we have available connections
	if stats.Primary.AcquireCount() >= int64(stats.Primary.MaxConns()) {
		return ComponentHealth{
			Status:    StatusDegraded,
			Message:   "Database connection pool exhausted",
			Timestamp: start,
			Duration:  time.Since(start),
		}
	}

	return ComponentHealth{
		Status:    StatusHealthy,
		Message:   fmt.Sprintf("Connected (pool: %d/%d)", stats.Primary.AcquiredConns, stats.Primary.MaxConns),
		Timestamp: start,
		Duration:  time.Since(start),
	}
}

// ReadinessChecker checks if the application is ready to serve requests
type ReadinessChecker struct {
	checkers []Checker
}

// NewReadinessChecker creates a new readiness checker
func NewReadinessChecker(checkers ...Checker) *ReadinessChecker {
	return &ReadinessChecker{checkers: checkers}
}

// Name returns the name of this checker
func (c *ReadinessChecker) Name() string {
	return "readiness"
}

// Check performs readiness checks
func (c *ReadinessChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	for _, checker := range c.checkers {
		health := checker.Check(ctx)
		if health.Status == StatusUnhealthy {
			return ComponentHealth{
				Status:    StatusUnhealthy,
				Message:   fmt.Sprintf("Component %s is unhealthy: %s", checker.Name(), health.Message),
				Timestamp: start,
				Duration:  time.Since(start),
			}
		}
	}

	return ComponentHealth{
		Status:    StatusHealthy,
		Message:   "All components ready",
		Timestamp: start,
		Duration:  time.Since(start),
	}
}

// LivenessChecker performs basic liveness checks
type LivenessChecker struct{}

// NewLivenessChecker creates a new liveness checker
func NewLivenessChecker() *LivenessChecker {
	return &LivenessChecker{}
}

// Name returns the name of this checker
func (c *LivenessChecker) Name() string {
	return "liveness"
}

// Check performs liveness check
func (c *LivenessChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Basic liveness check - if we can execute this, we're alive
	return ComponentHealth{
		Status:    StatusHealthy,
		Message:   "Application is alive",
		Timestamp: start,
		Duration:  time.Since(start),
	}
}

// RedisChecker implements health checking for Redis cache
type RedisChecker struct {
	client *redis.Client
}

// NewRedisChecker creates a new Redis health checker
func NewRedisChecker(client *redis.Client) *RedisChecker {
	return &RedisChecker{client: client}
}

// Name returns the name of this health checker
func (c *RedisChecker) Name() string {
	return "redis"
}

// Check performs the Redis health check
func (c *RedisChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Check Redis connection with ping
	if err := c.client.Ping(ctx).Err(); err != nil {
		return ComponentHealth{
			Status:    StatusUnhealthy,
			Message:   fmt.Sprintf("Redis connection failed: %v", err),
			Timestamp: start,
			Duration:  time.Since(start),
		}
	}

	// Get Redis info
	info, err := c.client.Info(ctx, "memory").Result()
	log.Println("Redis Info:", info)
	if err != nil {
		return ComponentHealth{
			Status:    StatusDegraded,
			Message:   fmt.Sprintf("Redis info command failed: %v", err),
			Timestamp: start,
			Duration:  time.Since(start),
		}
	}

	// Basic check - if we can ping and get info, Redis is healthy
	return ComponentHealth{
		Status:    StatusHealthy,
		Message:   "Redis connection healthy",
		Timestamp: start,
		Duration:  time.Since(start),
	}
}
