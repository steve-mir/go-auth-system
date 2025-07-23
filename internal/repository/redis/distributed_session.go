package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DistributedSessionManager manages sessions across multiple application instances
type DistributedSessionManager struct {
	sessionStore  *SessionStore
	client        *Client
	instanceID    string
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	mu            sync.RWMutex
	activeCleanup bool
}

// SessionMetrics holds metrics about session usage across instances
type SessionMetrics struct {
	TotalSessions    int64     `json:"total_sessions"`
	ActiveSessions   int64     `json:"active_sessions"`
	ExpiredSessions  int64     `json:"expired_sessions"`
	InstanceSessions int64     `json:"instance_sessions"`
	LastCleanup      time.Time `json:"last_cleanup"`
}

// NewDistributedSessionManager creates a new distributed session manager
func NewDistributedSessionManager(client *Client, instanceID string) *DistributedSessionManager {
	return &DistributedSessionManager{
		sessionStore: NewSessionStore(client),
		client:       client,
		instanceID:   instanceID,
		stopCleanup:  make(chan struct{}),
	}
}

// Start begins the distributed session management
func (dsm *DistributedSessionManager) Start(ctx context.Context, cleanupInterval time.Duration) error {
	dsm.mu.Lock()
	defer dsm.mu.Unlock()

	if dsm.activeCleanup {
		return fmt.Errorf("distributed session manager already started")
	}

	// Start cleanup ticker
	dsm.cleanupTicker = time.NewTicker(cleanupInterval)
	dsm.activeCleanup = true

	// Start cleanup goroutine
	go dsm.cleanupLoop(ctx)

	return nil
}

// Stop stops the distributed session management
func (dsm *DistributedSessionManager) Stop() error {
	dsm.mu.Lock()
	defer dsm.mu.Unlock()

	if !dsm.activeCleanup {
		return nil
	}

	close(dsm.stopCleanup)
	if dsm.cleanupTicker != nil {
		dsm.cleanupTicker.Stop()
	}
	dsm.activeCleanup = false

	return nil
}

// CreateSession creates a new session with distributed coordination
func (dsm *DistributedSessionManager) CreateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	// Add instance tracking
	data.CreatedAt = time.Now()
	data.LastUsed = time.Now()

	// Store session
	if err := dsm.sessionStore.Store(ctx, sessionID, data, ttl); err != nil {
		return err
	}

	// Update instance metrics
	return dsm.updateInstanceMetrics(ctx, "create", 1)
}

// GetSession retrieves a session with distributed coordination
func (dsm *DistributedSessionManager) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	data, err := dsm.sessionStore.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Update last used time across all instances
	data.LastUsed = time.Now()
	if err := dsm.sessionStore.Update(ctx, sessionID, data, time.Until(data.ExpiresAt)); err != nil {
		// Log error but don't fail the get operation
		// This ensures session retrieval works even if update fails
	}

	return data, nil
}

// UpdateSession updates a session with distributed coordination
func (dsm *DistributedSessionManager) UpdateSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	return dsm.sessionStore.Update(ctx, sessionID, data, ttl)
}

// DeleteSession deletes a session with distributed coordination
func (dsm *DistributedSessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	if err := dsm.sessionStore.Delete(ctx, sessionID); err != nil {
		return err
	}

	// Update instance metrics
	return dsm.updateInstanceMetrics(ctx, "delete", -1)
}

// DeleteUserSessions deletes all sessions for a user across all instances
func (dsm *DistributedSessionManager) DeleteUserSessions(ctx context.Context, userID string) error {
	// Get count of user sessions before deletion for metrics
	sessions, err := dsm.sessionStore.GetUserSessions(ctx, userID)
	if err != nil {
		return err
	}

	// Delete user sessions
	if err := dsm.sessionStore.DeleteUserSessions(ctx, userID); err != nil {
		return err
	}

	// Update metrics
	if len(sessions) > 0 {
		return dsm.updateInstanceMetrics(ctx, "delete", -int64(len(sessions)))
	}

	return nil
}

// GetSessionMetrics returns session metrics across all instances
func (dsm *DistributedSessionManager) GetSessionMetrics(ctx context.Context) (*SessionMetrics, error) {
	// Get total session count
	pattern := dsm.sessionStore.prefix + "*"
	keys, err := dsm.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session keys: %w", err)
	}

	totalSessions := int64(len(keys))
	activeSessions := int64(0)
	expiredSessions := int64(0)

	now := time.Now()
	for _, key := range keys {
		jsonData, err := dsm.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var data SessionData
		if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
			continue
		}

		if now.Before(data.ExpiresAt) {
			activeSessions++
		} else {
			expiredSessions++
		}
	}

	// Get instance-specific metrics
	instanceMetrics, err := dsm.getInstanceMetrics(ctx)
	if err != nil {
		instanceMetrics = 0
	}

	// Get last cleanup time
	lastCleanup, err := dsm.getLastCleanupTime(ctx)
	if err != nil {
		lastCleanup = time.Time{}
	}

	return &SessionMetrics{
		TotalSessions:    totalSessions,
		ActiveSessions:   activeSessions,
		ExpiredSessions:  expiredSessions,
		InstanceSessions: instanceMetrics,
		LastCleanup:      lastCleanup,
	}, nil
}

// cleanupLoop runs the distributed cleanup process
func (dsm *DistributedSessionManager) cleanupLoop(ctx context.Context) {
	for {
		select {
		case <-dsm.stopCleanup:
			return
		case <-dsm.cleanupTicker.C:
			if err := dsm.performDistributedCleanup(ctx); err != nil {
				// Log error but continue cleanup loop
				continue
			}
		case <-ctx.Done():
			return
		}
	}
}

// performDistributedCleanup performs cleanup with distributed coordination
func (dsm *DistributedSessionManager) performDistributedCleanup(ctx context.Context) error {
	// Use Redis lock to ensure only one instance performs cleanup at a time
	lockKey := "session_cleanup_lock"
	lockTTL := 5 * time.Minute

	// Try to acquire lock
	acquired, err := dsm.client.SetNX(ctx, lockKey, dsm.instanceID, lockTTL).Result()
	if err != nil {
		return fmt.Errorf("failed to acquire cleanup lock: %w", err)
	}

	if !acquired {
		// Another instance is already performing cleanup
		return nil
	}

	// Ensure lock is released
	defer dsm.client.Del(ctx, lockKey)

	// Perform cleanup
	if err := dsm.sessionStore.CleanupExpired(ctx); err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	// Update last cleanup time
	if err := dsm.setLastCleanupTime(ctx, time.Now()); err != nil {
		return fmt.Errorf("failed to update last cleanup time: %w", err)
	}

	return nil
}

// updateInstanceMetrics updates metrics for this instance
func (dsm *DistributedSessionManager) updateInstanceMetrics(ctx context.Context, operation string, delta int64) error {
	metricsKey := fmt.Sprintf("session_metrics:%s", dsm.instanceID)

	// Use atomic increment/decrement
	if delta != 0 {
		_, err := dsm.client.IncrBy(ctx, metricsKey, delta).Result()
		if err != nil {
			return fmt.Errorf("failed to update instance metrics: %w", err)
		}

		// Set expiration to prevent stale metrics
		dsm.client.Expire(ctx, metricsKey, 24*time.Hour)
	}

	return nil
}

// getInstanceMetrics gets metrics for this instance
func (dsm *DistributedSessionManager) getInstanceMetrics(ctx context.Context) (int64, error) {
	metricsKey := fmt.Sprintf("session_metrics:%s", dsm.instanceID)

	result, err := dsm.client.Get(ctx, metricsKey).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, err
	}

	var metrics int64
	if err := json.Unmarshal([]byte(result), &metrics); err != nil {
		// Try parsing as simple integer
		if _, parseErr := fmt.Sscanf(result, "%d", &metrics); parseErr != nil {
			return 0, fmt.Errorf("failed to parse instance metrics: %w", err)
		}
	}

	return metrics, nil
}

// setLastCleanupTime sets the last cleanup time
func (dsm *DistributedSessionManager) setLastCleanupTime(ctx context.Context, t time.Time) error {
	key := "session_last_cleanup"
	return dsm.client.Set(ctx, key, t.Unix(), 24*time.Hour).Err()
}

// getLastCleanupTime gets the last cleanup time
func (dsm *DistributedSessionManager) getLastCleanupTime(ctx context.Context) (time.Time, error) {
	key := "session_last_cleanup"
	result, err := dsm.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}

	var timestamp int64
	if _, err := fmt.Sscanf(result, "%d", &timestamp); err != nil {
		return time.Time{}, err
	}

	return time.Unix(timestamp, 0), nil
}

// GetActiveInstances returns a list of active instances managing sessions
func (dsm *DistributedSessionManager) GetActiveInstances(ctx context.Context) ([]string, error) {
	pattern := "session_metrics:*"
	keys, err := dsm.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance keys: %w", err)
	}

	var instances []string
	for _, key := range keys {
		// Extract instance ID from key
		if len(key) > len("session_metrics:") {
			instanceID := key[len("session_metrics:"):]
			instances = append(instances, instanceID)
		}
	}

	return instances, nil
}
