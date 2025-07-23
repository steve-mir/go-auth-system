package postgres

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/steve-mir/go-auth-system/internal/config"
)

// DB wraps the pgxpool.Pool to provide additional functionality with read replica support
type DB struct {
	primary      *pgxpool.Pool
	readReplicas []*ReadReplica
	strategy     LoadBalanceStrategy
	mu           sync.RWMutex
	roundRobin   int64
}

// ReadReplica represents a read replica connection
type ReadReplica struct {
	pool        *pgxpool.Pool
	config      config.ReadReplicaConfig
	healthy     bool
	connections int64
	lastCheck   time.Time
	mu          sync.RWMutex
}

// LoadBalanceStrategy defines the strategy for load balancing read queries
type LoadBalanceStrategy string

const (
	RoundRobin         LoadBalanceStrategy = "round_robin"
	Random             LoadBalanceStrategy = "random"
	LeastConnections   LoadBalanceStrategy = "least_connections"
	WeightedRoundRobin LoadBalanceStrategy = "weighted_round_robin"
)

// ConnectionStats provides statistics about database connections
type ConnectionStats struct {
	Primary      *pgxpool.Stat  `json:"primary"`
	ReadReplicas []ReplicaStats `json:"read_replicas"`
	Strategy     string         `json:"strategy"`
	TotalReads   int64          `json:"total_reads"`
	TotalWrites  int64          `json:"total_writes"`
}

// ReplicaStats provides statistics about a read replica
type ReplicaStats struct {
	Host        string        `json:"host"`
	Port        int           `json:"port"`
	Healthy     bool          `json:"healthy"`
	Stats       *pgxpool.Stat `json:"stats"`
	Connections int64         `json:"connections"`
	Weight      int           `json:"weight"`
	Priority    int           `json:"priority"`
}

// NewConnection creates a new database connection with read replica support
func NewConnection(cfg *config.DatabaseConfig) (*DB, error) {
	db := &DB{
		strategy: LoadBalanceStrategy(cfg.ReadStrategy),
	}

	// Default to round robin if strategy not specified
	if db.strategy == "" {
		db.strategy = RoundRobin
	}

	// Create primary connection
	primary, err := createConnectionPool(cfg, cfg.Host, cfg.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary connection: %w", err)
	}
	db.primary = primary

	// Create read replica connections
	if len(cfg.ReadReplicas) > 0 {
		db.readReplicas = make([]*ReadReplica, 0, len(cfg.ReadReplicas))

		for _, replicaCfg := range cfg.ReadReplicas {
			replica, err := createReadReplica(cfg, replicaCfg)
			if err != nil {
				// Log error but don't fail - continue with available replicas
				continue
			}
			db.readReplicas = append(db.readReplicas, replica)
		}
	}

	// Start health check routine for read replicas
	if len(db.readReplicas) > 0 {
		go db.healthCheckLoop()
	}

	return db, nil
}

// createConnectionPool creates a connection pool for the given host and port
func createConnectionPool(cfg *config.DatabaseConfig, host string, port int) (*pgxpool.Pool, error) {
	// Build connection string
	connStr := buildConnectionString(cfg, host, port)

	// Configure connection pool
	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	// Set pool configuration
	poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.MaxIdleConns)
	poolConfig.MaxConnLifetime = time.Duration(cfg.ConnMaxLifetime) * time.Second
	poolConfig.MaxConnIdleTime = time.Duration(cfg.ConnMaxIdleTime) * time.Second

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}

// createReadReplica creates a read replica connection
func createReadReplica(cfg *config.DatabaseConfig, replicaCfg config.ReadReplicaConfig) (*ReadReplica, error) {
	pool, err := createConnectionPool(cfg, replicaCfg.Host, replicaCfg.Port)
	if err != nil {
		return nil, err
	}

	return &ReadReplica{
		pool:      pool,
		config:    replicaCfg,
		healthy:   true,
		lastCheck: time.Now(),
	}, nil
}

// buildConnectionString constructs the PostgreSQL connection string
func buildConnectionString(cfg *config.DatabaseConfig, host string, port int) string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s&connect_timeout=%d",
		cfg.User,
		cfg.Password,
		host,
		port,
		cfg.Name,
		cfg.SSLMode,
		cfg.ConnectTimeout,
	)
}

// Primary returns the primary database connection for write operations
func (db *DB) Primary() *pgxpool.Pool {
	return db.primary
}

// ReadPool returns a read replica connection for read operations
func (db *DB) ReadPool() *pgxpool.Pool {
	// If no read replicas available, use primary
	if len(db.readReplicas) == 0 {
		return db.primary
	}

	// Get healthy replicas
	healthyReplicas := db.getHealthyReplicas()
	if len(healthyReplicas) == 0 {
		return db.primary
	}

	// Select replica based on strategy
	replica := db.selectReplica(healthyReplicas)
	if replica == nil {
		return db.primary
	}

	// Increment connection counter
	atomic.AddInt64(&replica.connections, 1)

	return replica.pool
}

// getHealthyReplicas returns a list of healthy read replicas
func (db *DB) getHealthyReplicas() []*ReadReplica {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var healthy []*ReadReplica
	for _, replica := range db.readReplicas {
		replica.mu.RLock()
		if replica.healthy {
			healthy = append(healthy, replica)
		}
		replica.mu.RUnlock()
	}

	return healthy
}

// selectReplica selects a read replica based on the configured strategy
func (db *DB) selectReplica(replicas []*ReadReplica) *ReadReplica {
	if len(replicas) == 0 {
		return nil
	}

	switch db.strategy {
	case Random:
		return replicas[rand.Intn(len(replicas))]

	case LeastConnections:
		var selected *ReadReplica
		var minConnections int64 = -1

		for _, replica := range replicas {
			connections := atomic.LoadInt64(&replica.connections)
			if minConnections == -1 || connections < minConnections {
				minConnections = connections
				selected = replica
			}
		}
		return selected

	case WeightedRoundRobin:
		// Simple weighted selection based on weight
		totalWeight := 0
		for _, replica := range replicas {
			totalWeight += replica.config.Weight
		}

		if totalWeight == 0 {
			return replicas[0]
		}

		target := rand.Intn(totalWeight)
		current := 0

		for _, replica := range replicas {
			current += replica.config.Weight
			if current > target {
				return replica
			}
		}
		return replicas[0]

	default: // RoundRobin
		index := atomic.AddInt64(&db.roundRobin, 1) % int64(len(replicas))
		return replicas[index]
	}
}

// healthCheckLoop periodically checks the health of read replicas
func (db *DB) healthCheckLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		db.checkReplicaHealth()
	}
}

// checkReplicaHealth checks the health of all read replicas
func (db *DB) checkReplicaHealth() {
	db.mu.RLock()
	replicas := make([]*ReadReplica, len(db.readReplicas))
	copy(replicas, db.readReplicas)
	db.mu.RUnlock()

	for _, replica := range replicas {
		go func(r *ReadReplica) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			healthy := r.pool.Ping(ctx) == nil

			r.mu.Lock()
			r.healthy = healthy
			r.lastCheck = time.Now()
			r.mu.Unlock()
		}(replica)
	}
}

// Close closes all database connections
func (db *DB) Close() {
	if db.primary != nil {
		db.primary.Close()
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	for _, replica := range db.readReplicas {
		if replica.pool != nil {
			replica.pool.Close()
		}
	}
}

// Health checks the health of primary and read replica connections
func (db *DB) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Check primary
	if err := db.primary.Ping(ctx); err != nil {
		return fmt.Errorf("primary database unhealthy: %w", err)
	}

	// Check read replicas
	db.mu.RLock()
	replicas := make([]*ReadReplica, len(db.readReplicas))
	copy(replicas, db.readReplicas)
	db.mu.RUnlock()

	for _, replica := range replicas {
		if err := replica.pool.Ping(ctx); err != nil {
			replica.mu.Lock()
			replica.healthy = false
			replica.mu.Unlock()
		} else {
			replica.mu.Lock()
			replica.healthy = true
			replica.mu.Unlock()
		}
	}

	return nil
}

// Stats returns comprehensive connection statistics
func (db *DB) Stats() *ConnectionStats {
	stats := &ConnectionStats{
		Primary:  db.primary.Stat(),
		Strategy: string(db.strategy),
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	stats.ReadReplicas = make([]ReplicaStats, len(db.readReplicas))
	for i, replica := range db.readReplicas {
		replica.mu.RLock()
		stats.ReadReplicas[i] = ReplicaStats{
			Host:        replica.config.Host,
			Port:        replica.config.Port,
			Healthy:     replica.healthy,
			Stats:       replica.pool.Stat(),
			Connections: atomic.LoadInt64(&replica.connections),
			Weight:      replica.config.Weight,
			Priority:    replica.config.Priority,
		}
		replica.mu.RUnlock()
	}

	return stats
}

// GetReadReplicaCount returns the number of available read replicas
func (db *DB) GetReadReplicaCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.readReplicas)
}

// GetHealthyReadReplicaCount returns the number of healthy read replicas
func (db *DB) GetHealthyReadReplicaCount() int {
	return len(db.getHealthyReplicas())
}
