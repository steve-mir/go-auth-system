package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/steve-mir/go-auth-system/internal/config"
)

// Client wraps the Redis client with additional functionality
type Client struct {
	*redis.Client
	config *config.RedisConfig
}

// NewClient creates a new Redis client with connection pooling
func NewClient(cfg *config.RedisConfig) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis config cannot be nil")
	}

	// Create Redis client options
	opts := &redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,

		// Connection pool settings
		PoolTimeout: 30 * time.Second,
		// TODO: Include.
		// IdleTimeout:     5 * time.Minute,
		MaxRetries:      3,
		MinRetryBackoff: 8 * time.Millisecond,
		MaxRetryBackoff: 512 * time.Millisecond,
	}

	// Create Redis client
	rdb := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Client{
		Client: rdb,
		config: cfg,
	}, nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.Client.Close()
}

// Health checks the Redis connection health
func (c *Client) Health(ctx context.Context) error {
	return c.Ping(ctx).Err()
}

// GetStats returns Redis connection pool statistics
func (c *Client) GetStats() *redis.PoolStats {
	return c.PoolStats()
}

// FlushDB flushes the current database (use with caution)
func (c *Client) FlushDB(ctx context.Context) error {
	return c.Client.FlushDB(ctx).Err()
}

// FlushAll flushes all databases (use with extreme caution)
func (c *Client) FlushAll(ctx context.Context) error {
	return c.Client.FlushAll(ctx).Err()
}
