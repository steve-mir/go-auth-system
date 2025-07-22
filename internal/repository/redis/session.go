package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SessionData represents session information stored in Redis
type SessionData struct {
	UserID    string    `json:"user_id"`
	Roles     []string  `json:"roles"`
	ExpiresAt time.Time `json:"expires_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
}

// SessionStore handles session storage operations in Redis
type SessionStore struct {
	client *Client
	prefix string
}

// NewSessionStore creates a new session store
func NewSessionStore(client *Client) *SessionStore {
	return &SessionStore{
		client: client,
		prefix: "session:",
	}
}

// Store stores session data with automatic expiration
func (s *SessionStore) Store(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	if data == nil {
		return fmt.Errorf("session data cannot be nil")
	}

	// Set expiration time
	data.ExpiresAt = time.Now().Add(ttl)

	// Serialize session data
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Store in Redis with TTL
	key := s.prefix + sessionID
	if err := s.client.Set(ctx, key, jsonData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}

	return nil
}

// Get retrieves session data by session ID
func (s *SessionStore) Get(ctx context.Context, sessionID string) (*SessionData, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	key := s.prefix + sessionID
	jsonData, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var data SessionData
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Check if session has expired
	if time.Now().After(data.ExpiresAt) {
		// Delete expired session
		s.Delete(ctx, sessionID)
		return nil, fmt.Errorf("session has expired")
	}

	return &data, nil
}

// Update updates session data and refreshes TTL
func (s *SessionStore) Update(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	if data == nil {
		return fmt.Errorf("session data cannot be nil")
	}

	// Update last used time
	data.LastUsed = time.Now()
	data.ExpiresAt = time.Now().Add(ttl)

	// Serialize and store
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	key := s.prefix + sessionID
	if err := s.client.Set(ctx, key, jsonData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

// Delete removes a session from Redis
func (s *SessionStore) Delete(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	key := s.prefix + sessionID
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// Exists checks if a session exists
func (s *SessionStore) Exists(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return false, fmt.Errorf("session ID cannot be empty")
	}

	key := s.prefix + sessionID
	count, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}

	return count > 0, nil
}

// Extend extends the TTL of an existing session
func (s *SessionStore) Extend(ctx context.Context, sessionID string, ttl time.Duration) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	key := s.prefix + sessionID

	// Check if session exists
	exists, err := s.Exists(ctx, sessionID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("session not found")
	}

	// Extend TTL
	if err := s.client.Expire(ctx, key, ttl).Err(); err != nil {
		return fmt.Errorf("failed to extend session TTL: %w", err)
	}

	return nil
}

// GetUserSessions retrieves all sessions for a specific user
func (s *SessionStore) GetUserSessions(ctx context.Context, userID string) ([]*SessionData, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	// Get all session keys
	pattern := s.prefix + "*"
	keys, err := s.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session keys: %w", err)
	}

	var userSessions []*SessionData
	for _, key := range keys {
		jsonData, err := s.client.Get(ctx, key).Result()
		if err != nil {
			continue // Skip invalid sessions
		}

		var data SessionData
		if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
			continue // Skip invalid sessions
		}

		// Check if session belongs to the user and is not expired
		if data.UserID == userID && time.Now().Before(data.ExpiresAt) {
			userSessions = append(userSessions, &data)
		}
	}

	return userSessions, nil
}

// DeleteUserSessions deletes all sessions for a specific user
func (s *SessionStore) DeleteUserSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	// Get all user sessions
	sessions, err := s.GetUserSessions(ctx, userID)
	if err != nil {
		return err
	}

	// Delete each session
	for _, session := range sessions {
		// Extract session ID from the stored data (we need to find the key)
		pattern := s.prefix + "*"
		keys, err := s.client.Keys(ctx, pattern).Result()
		if err != nil {
			continue
		}

		for _, key := range keys {
			jsonData, err := s.client.Get(ctx, key).Result()
			if err != nil {
				continue
			}

			var data SessionData
			if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
				continue
			}

			if data.UserID == userID {
				s.client.Del(ctx, key)
			}
		}
	}

	return nil
}

// CleanupExpired removes expired sessions (should be called periodically)
func (s *SessionStore) CleanupExpired(ctx context.Context) error {
	pattern := s.prefix + "*"
	keys, err := s.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get session keys: %w", err)
	}

	now := time.Now()
	for _, key := range keys {
		jsonData, err := s.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var data SessionData
		if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
			// Delete invalid session data
			s.client.Del(ctx, key)
			continue
		}

		// Delete expired sessions
		if now.After(data.ExpiresAt) {
			s.client.Del(ctx, key)
		}
	}

	return nil
}
