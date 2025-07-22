package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
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
}

// NewService creates a new health service
func NewService() *Service {
	return &Service{
		checkers: make([]Checker, 0),
	}
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

		// Determine overall status
		if health.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
		} else if health.Status == StatusDegraded && overallStatus == StatusHealthy {
			overallStatus = StatusDegraded
		}
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
	if stats.AcquiredConns() >= stats.MaxConns() {
		return ComponentHealth{
			Status:    StatusDegraded,
			Message:   "Database connection pool exhausted",
			Timestamp: start,
			Duration:  time.Since(start),
		}
	}

	return ComponentHealth{
		Status:    StatusHealthy,
		Message:   fmt.Sprintf("Connected (pool: %d/%d)", stats.AcquiredConns(), stats.MaxConns()),
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
