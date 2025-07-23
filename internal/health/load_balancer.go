package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// LoadBalancerHealthService provides health checks specifically designed for load balancers
type LoadBalancerHealthService struct {
	service        *Service
	instanceID     string
	startTime      time.Time
	readyTime      time.Time
	shutdownSignal chan struct{}
	isReady        bool
	isShuttingDown bool
	mu             sync.RWMutex
}

// LoadBalancerConfig contains configuration for load balancer health checks
type LoadBalancerConfig struct {
	InstanceID          string        `yaml:"instance_id"`
	ReadinessTimeout    time.Duration `yaml:"readiness_timeout"`
	ShutdownTimeout     time.Duration `yaml:"shutdown_timeout"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`

	// Kubernetes specific settings
	LivenessPath  string `yaml:"liveness_path"`
	ReadinessPath string `yaml:"readiness_path"`
	HealthPath    string `yaml:"health_path"`

	// Load balancer specific settings
	DrainTimeout     time.Duration `yaml:"drain_timeout"`
	GracefulShutdown bool          `yaml:"graceful_shutdown"`
}

// DefaultLoadBalancerConfig returns default load balancer configuration
func DefaultLoadBalancerConfig() *LoadBalancerConfig {
	return &LoadBalancerConfig{
		ReadinessTimeout:    30 * time.Second,
		ShutdownTimeout:     30 * time.Second,
		HealthCheckInterval: 10 * time.Second,
		LivenessPath:        "/health/live",
		ReadinessPath:       "/health/ready",
		HealthPath:          "/health",
		DrainTimeout:        15 * time.Second,
		GracefulShutdown:    true,
	}
}

// NewLoadBalancerHealthService creates a new load balancer health service
func NewLoadBalancerHealthService(config *LoadBalancerConfig, db *postgres.DB, redisClient *redis.Client) *LoadBalancerHealthService {
	service := NewService()

	// Add standard health checkers
	service.AddChecker(NewDatabaseChecker(db))
	service.AddChecker(NewRedisChecker(redisClient))
	service.AddChecker(NewLoadBalancerReadinessChecker())

	return &LoadBalancerHealthService{
		service:        service,
		instanceID:     config.InstanceID,
		startTime:      time.Now(),
		shutdownSignal: make(chan struct{}),
		isReady:        false,
		isShuttingDown: false,
	}
}

// Start starts the load balancer health service
func (lbhs *LoadBalancerHealthService) Start(ctx context.Context) error {
	// Wait for readiness
	go lbhs.waitForReadiness(ctx)

	return nil
}

// waitForReadiness waits for the service to become ready
func (lbhs *LoadBalancerHealthService) waitForReadiness(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			health := lbhs.service.Check(ctx)

			// Check if all critical components are healthy
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

			lbhs.mu.Lock()
			if ready && !lbhs.isReady {
				lbhs.isReady = true
				lbhs.readyTime = time.Now()
			}
			lbhs.mu.Unlock()

			if ready {
				return
			}
		}
	}
}

// MarkReady manually marks the service as ready
func (lbhs *LoadBalancerHealthService) MarkReady() {
	lbhs.mu.Lock()
	defer lbhs.mu.Unlock()

	lbhs.isReady = true
	lbhs.readyTime = time.Now()
}

// MarkNotReady manually marks the service as not ready
func (lbhs *LoadBalancerHealthService) MarkNotReady() {
	lbhs.mu.Lock()
	defer lbhs.mu.Unlock()

	lbhs.isReady = false
}

// InitiateShutdown initiates graceful shutdown
func (lbhs *LoadBalancerHealthService) InitiateShutdown() {
	lbhs.mu.Lock()
	defer lbhs.mu.Unlock()

	if !lbhs.isShuttingDown {
		lbhs.isShuttingDown = true
		close(lbhs.shutdownSignal)
	}
}

// IsShuttingDown returns whether the service is shutting down
func (lbhs *LoadBalancerHealthService) IsShuttingDown() bool {
	lbhs.mu.RLock()
	defer lbhs.mu.RUnlock()
	return lbhs.isShuttingDown
}

// LivenessHandler returns a liveness probe handler optimized for load balancers
func (lbhs *LoadBalancerHealthService) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lbhs.mu.RLock()
		isShuttingDown := lbhs.isShuttingDown
		lbhs.mu.RUnlock()

		// During shutdown, we're still alive but not accepting new requests
		if isShuttingDown {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			response := map[string]interface{}{
				"status":        "alive",
				"shutting_down": true,
				"timestamp":     time.Now(),
				"instance_id":   lbhs.instanceID,
				"uptime":        time.Since(lbhs.startTime).String(),
			}

			json.NewEncoder(w).Encode(response)
			return
		}

		// Standard liveness check
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"status":      "alive",
			"timestamp":   time.Now(),
			"instance_id": lbhs.instanceID,
			"uptime":      time.Since(lbhs.startTime).String(),
		}

		json.NewEncoder(w).Encode(response)
	}
}

// ReadinessHandler returns a readiness probe handler optimized for load balancers
func (lbhs *LoadBalancerHealthService) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lbhs.mu.RLock()
		isReady := lbhs.isReady
		isShuttingDown := lbhs.isShuttingDown
		readyTime := lbhs.readyTime
		lbhs.mu.RUnlock()

		// Not ready if shutting down or not initialized
		if isShuttingDown || !isReady {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)

			response := map[string]interface{}{
				"status":        "not_ready",
				"ready":         false,
				"shutting_down": isShuttingDown,
				"timestamp":     time.Now(),
				"instance_id":   lbhs.instanceID,
				"uptime":        time.Since(lbhs.startTime).String(),
			}

			json.NewEncoder(w).Encode(response)
			return
		}

		// Check dependencies
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		health := lbhs.service.Check(ctx)

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

		w.Header().Set("Content-Type", "application/json")

		if ready {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		response := map[string]interface{}{
			"status":      map[bool]string{true: "ready", false: "not_ready"}[ready],
			"ready":       ready,
			"timestamp":   time.Now(),
			"instance_id": lbhs.instanceID,
			"uptime":      time.Since(lbhs.startTime).String(),
			"ready_since": readyTime,
			"components":  health.Components,
		}

		json.NewEncoder(w).Encode(response)
	}
}

// HealthHandler returns a comprehensive health handler for load balancers
func (lbhs *LoadBalancerHealthService) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		health := lbhs.service.Check(ctx)

		lbhs.mu.RLock()
		isReady := lbhs.isReady
		isShuttingDown := lbhs.isShuttingDown
		readyTime := lbhs.readyTime
		lbhs.mu.RUnlock()

		// Enhanced health response with load balancer specific information
		response := map[string]interface{}{
			"status":        health.Status,
			"timestamp":     health.Timestamp,
			"components":    health.Components,
			"instance_id":   lbhs.instanceID,
			"uptime":        time.Since(lbhs.startTime).String(),
			"ready":         isReady,
			"ready_since":   readyTime,
			"shutting_down": isShuttingDown,
		}

		w.Header().Set("Content-Type", "application/json")

		// Set appropriate HTTP status code
		switch health.Status {
		case StatusHealthy:
			if isShuttingDown {
				w.WriteHeader(http.StatusServiceUnavailable)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		case StatusDegraded:
			w.WriteHeader(http.StatusOK) // Still return 200 for degraded
		case StatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(response)
	}
}

// DrainHandler returns a handler to initiate connection draining
func (lbhs *LoadBalancerHealthService) DrainHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		lbhs.InitiateShutdown()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := map[string]interface{}{
			"status":      "draining",
			"message":     "Connection draining initiated",
			"timestamp":   time.Now(),
			"instance_id": lbhs.instanceID,
		}

		json.NewEncoder(w).Encode(response)
	}
}

// LoadBalancerReadinessChecker implements readiness checking for load balancers
type LoadBalancerReadinessChecker struct {
	startTime time.Time
}

// NewLoadBalancerReadinessChecker creates a new load balancer readiness checker
func NewLoadBalancerReadinessChecker() *LoadBalancerReadinessChecker {
	return &LoadBalancerReadinessChecker{
		startTime: time.Now(),
	}
}

// Name returns the name of this checker
func (c *LoadBalancerReadinessChecker) Name() string {
	return "load_balancer_readiness"
}

// Check performs the readiness check
func (c *LoadBalancerReadinessChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()

	// Simple readiness check - service has been running for at least 5 seconds
	if time.Since(c.startTime) < 5*time.Second {
		return ComponentHealth{
			Status:    StatusUnhealthy,
			Message:   "Service still initializing",
			Timestamp: start,
			Duration:  time.Since(start),
		}
	}

	return ComponentHealth{
		Status:    StatusHealthy,
		Message:   "Load balancer ready",
		Timestamp: start,
		Duration:  time.Since(start),
	}
}
