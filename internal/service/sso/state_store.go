package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/steve-mir/go-auth-system/internal/repository/redis"
)

// RedisStateStore implements StateStore using Redis
type RedisStateStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

// NewRedisStateStore creates a new Redis-based state store
func NewRedisStateStore(client *redis.Client) StateStore {
	return &RedisStateStore{
		client: client,
		prefix: "oauth_state:",
		ttl:    10 * time.Minute, // OAuth states expire in 10 minutes
	}
}

// StoreState stores an OAuth state in Redis
func (r *RedisStateStore) StoreState(ctx context.Context, state *OAuthState) error {
	key := r.getKey(state.State)

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal OAuth state: %w", err)
	}

	err = r.client.Set(ctx, key, data, r.ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store OAuth state in Redis: %w", err)
	}

	return nil
}

// GetState retrieves an OAuth state from Redis
func (r *RedisStateStore) GetState(ctx context.Context, stateKey string) (*OAuthState, error) {
	key := r.getKey(stateKey)

	data, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == nil {
			return nil, fmt.Errorf("OAuth state not found or expired")
		}
		return nil, fmt.Errorf("failed to get OAuth state from Redis: %w", err)
	}

	var state OAuthState
	if err := json.Unmarshal([]byte(data), &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OAuth state: %w", err)
	}

	return &state, nil
}

// DeleteState removes an OAuth state from Redis
func (r *RedisStateStore) DeleteState(ctx context.Context, stateKey string) error {
	key := r.getKey(stateKey)

	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete OAuth state from Redis: %w", err)
	}

	return nil
}

// getKey generates the Redis key for a state
func (r *RedisStateStore) getKey(state string) string {
	return r.prefix + state
}
