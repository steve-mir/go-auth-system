package scaling

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/health"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// ScalingManager manages horizontal scaling components
type ScalingManager struct {
	config                    *config.Config
	instanceID                string
	db                        *postgres.DB
	redisClient               *redis.Client
	distributedSessionManager *redis.DistributedSessionManager
	distributedRateLimiter    *redis.DistributedRateLimiter
	loadBalancerHealth        *health.LoadBalancerHealthService

	// Lifecycle management
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
	mu      sync.RWMutex
}

// ScalingConfig contains configuration for horizontal scaling
type ScalingConfig struct {
	InstanceID               string        `yaml:"instance_id"`
	SessionCleanupInterval   time.Duration `yaml:"session_cleanup_interval"`
	RateLimitCleanupInterval time.Duration `yaml:"rate_limit_cleanup_interval"`
	HealthCheckInterval      time.Duration `yaml:"health_check_interval"`
	MetricsUpdateInterval    time.Duration `yaml:"metrics_update_interval"`
	GracefulShutdownTimeout  time.Duration `yaml:"graceful_shutdown_timeout"`
}

// DefaultScalingConfig returns default scaling configuration
func DefaultScalingConfig() *ScalingConfig {
	return &ScalingConfig{
		InstanceID:               getInstanceID(),
		SessionCleanupInterval:   5 * time.Minute,
		RateLimitCleanupInterval: 2 * time.Minute,
		HealthCheckInterval:      30 * time.Second,
		MetricsUpdateInterval:    10 * time.Second,
		GracefulShutdownTimeout:  30 * time.Second,
	}
}

// NewScalingManager creates a new scaling manager
func NewScalingManager(cfg *config.Config, db *postgres.DB, redisClient *redis.Client) (*ScalingManager, error) {
	scalingConfig := DefaultScalingConfig()

	// Override instance ID if provided in environment
	if envInstanceID := os.Getenv("INSTANCE_ID"); envInstanceID != "" {
		scalingConfig.InstanceID = envInstanceID
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create distributed components
	distributedSessionManager := redis.NewDistributedSessionManager(redisClient, scalingConfig.InstanceID)
	distributedRateLimiter := redis.NewDistributedRateLimiter(redisClient, scalingConfig.InstanceID, time.Minute)

	// Create load balancer health service
	lbConfig := health.DefaultLoadBalancerConfig()
	lbConfig.InstanceID = scalingConfig.InstanceID
	loadBalancerHealth := health.NewLoadBalancerHealthService(lbConfig, db, redisClient)

	return &ScalingManager{
		config:                    cfg,
		instanceID:                scalingConfig.InstanceID,
		db:                        db,
		redisClient:               redisClient,
		distributedSessionManager: distributedSessionManager,
		distributedRateLimiter:    distributedRateLimiter,
		loadBalancerHealth:        loadBalancerHealth,
		ctx:                       ctx,
		cancel:                    cancel,
	}, nil
}

// Start starts all horizontal scaling components
func (sm *ScalingManager) Start() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.started {
		return fmt.Errorf("scaling manager already started")
	}

	// Start distributed session manager
	if err := sm.distributedSessionManager.Start(sm.ctx, 5*time.Minute); err != nil {
		return fmt.Errorf("failed to start distributed session manager: %w", err)
	}

	// Start load balancer health service
	if err := sm.loadBalancerHealth.Start(sm.ctx); err != nil {
		return fmt.Errorf("failed to start load balancer health service: %w", err)
	}

	// Start background tasks
	sm.wg.Add(3)
	go sm.rateLimitCleanupLoop()
	go sm.metricsUpdateLoop()
	go sm.healthMonitoringLoop()

	sm.started = true
	return nil
}

// Stop gracefully stops all horizontal scaling components
func (sm *ScalingManager) Stop() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.started {
		return nil
	}

	// Initiate graceful shutdown
	sm.loadBalancerHealth.InitiateShutdown()

	// Cancel context to stop background tasks
	sm.cancel()

	// Wait for background tasks to complete
	done := make(chan struct{})
	go func() {
		sm.wg.Wait()
		close(done)
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-done:
		// All tasks completed gracefully
	case <-time.After(30 * time.Second):
		// Timeout - force shutdown
	}

	// Stop distributed components
	if err := sm.distributedSessionManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop distributed session manager: %w", err)
	}

	sm.started = false
	return nil
}

// GetInstanceID returns the current instance ID
func (sm *ScalingManager) GetInstanceID() string {
	return sm.instanceID
}

// GetDistributedSessionManager returns the distributed session manager
func (sm *ScalingManager) GetDistributedSessionManager() *redis.DistributedSessionManager {
	return sm.distributedSessionManager
}

// GetDistributedRateLimiter returns the distributed rate limiter
func (sm *ScalingManager) GetDistributedRateLimiter() *redis.DistributedRateLimiter {
	return sm.distributedRateLimiter
}

// GetLoadBalancerHealthService returns the load balancer health service
func (sm *ScalingManager) GetLoadBalancerHealthService() *health.LoadBalancerHealthService {
	return sm.loadBalancerHealth
}

// GetScalingMetrics returns current scaling metrics
func (sm *ScalingManager) GetScalingMetrics(ctx context.Context) (*ScalingMetrics, error) {
	// Get session metrics
	sessionMetrics, err := sm.distributedSessionManager.GetSessionMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get session metrics: %w", err)
	}

	// Get rate limiter metrics
	rateLimiterMetrics := sm.distributedRateLimiter.GetMetrics()

	// Get database connection stats
	dbStats := sm.db.Stats()

	// Get active instances
	activeInstances, err := sm.distributedSessionManager.GetActiveInstances(ctx)
	if err != nil {
		activeInstances = []string{sm.instanceID}
	}

	return &ScalingMetrics{
		InstanceID:         sm.instanceID,
		ActiveInstances:    activeInstances,
		SessionMetrics:     sessionMetrics,
		RateLimiterMetrics: rateLimiterMetrics,
		DatabaseStats:      dbStats,
		Timestamp:          time.Now(),
	}, nil
}

// rateLimitCleanupLoop runs periodic cleanup of rate limit data
func (sm *ScalingManager) rateLimitCleanupLoop() {
	defer sm.wg.Done()

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			if err := sm.distributedRateLimiter.CleanupExpired(sm.ctx); err != nil {
				// Log error but continue
				continue
			}
		}
	}
}

// metricsUpdateLoop periodically updates scaling metrics
func (sm *ScalingManager) metricsUpdateLoop() {
	defer sm.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// Update metrics (this would integrate with monitoring system)
			_, err := sm.GetScalingMetrics(sm.ctx)
			if err != nil {
				// Log error but continue
				continue
			}
		}
	}
}

// healthMonitoringLoop monitors the health of scaling components
func (sm *ScalingManager) healthMonitoringLoop() {
	defer sm.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// Check database health
			if err := sm.db.Health(sm.ctx); err != nil {
				// Database unhealthy - mark service as not ready
				sm.loadBalancerHealth.MarkNotReady()
			} else {
				// Database healthy - mark service as ready
				sm.loadBalancerHealth.MarkReady()
			}

			// Check Redis health
			if err := sm.redisClient.Ping(sm.ctx).Err(); err != nil {
				// Redis unhealthy - this affects session management
				// Could implement fallback strategies here
			}
		}
	}
}

// ScalingMetrics holds comprehensive scaling metrics
type ScalingMetrics struct {
	InstanceID         string                    `json:"instance_id"`
	ActiveInstances    []string                  `json:"active_instances"`
	SessionMetrics     *redis.SessionMetrics     `json:"session_metrics"`
	RateLimiterMetrics *redis.InstanceMetrics    `json:"rate_limiter_metrics"`
	DatabaseStats      *postgres.ConnectionStats `json:"database_stats"`
	Timestamp          time.Time                 `json:"timestamp"`
}

// getInstanceID generates or retrieves the instance ID
func getInstanceID() string {
	// Try to get from environment (Kubernetes pod name)
	if instanceID := os.Getenv("INSTANCE_ID"); instanceID != "" {
		return instanceID
	}

	// Try to get from hostname
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}

	// Fallback to a generated ID
	return fmt.Sprintf("instance-%d", time.Now().Unix())
}

// IsHealthy returns whether the scaling manager is healthy
func (sm *ScalingManager) IsHealthy(ctx context.Context) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.started {
		return false
	}

	// Check if shutting down
	if sm.loadBalancerHealth.IsShuttingDown() {
		return false
	}

	// Check database health
	if err := sm.db.Health(ctx); err != nil {
		return false
	}

	// Check Redis health
	if err := sm.redisClient.Ping(ctx).Err(); err != nil {
		return false
	}

	return true
}

// IsReady returns whether the scaling manager is ready to serve requests
func (sm *ScalingManager) IsReady(ctx context.Context) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.started {
		return false
	}

	// Check if shutting down
	if sm.loadBalancerHealth.IsShuttingDown() {
		return false
	}

	// All components must be healthy for readiness
	return sm.IsHealthy(ctx)
}
