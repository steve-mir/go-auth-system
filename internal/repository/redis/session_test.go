package redis

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

func setupTestClient(t *testing.T) *Client {
	cfg := &config.RedisConfig{
		Host:         "localhost",
		Port:         6379,
		DB:           1, // Use different DB for tests
		PoolSize:     10,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	// Clean test database
	ctx := context.Background()
	client.FlushDB(ctx)

	return client
}

func TestSessionStore_Store(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	store := NewSessionStore(client)
	ctx := context.Background()

	sessionData := &SessionData{
		UserID:    "user123",
		Roles:     []string{"user", "admin"},
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	tests := []struct {
		name      string
		sessionID string
		data      *SessionData
		ttl       time.Duration
		wantErr   bool
	}{
		{
			name:      "valid session",
			sessionID: "session123",
			data:      sessionData,
			ttl:       time.Hour,
			wantErr:   false,
		},
		{
			name:      "empty session ID",
			sessionID: "",
			data:      sessionData,
			ttl:       time.Hour,
			wantErr:   true,
		},
		{
			name:      "nil data",
			sessionID: "session123",
			data:      nil,
			ttl:       time.Hour,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Store(ctx, tt.sessionID, tt.data, tt.ttl)
			if (err != nil) != tt.wantErr {
				t.Errorf("Store() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSessionStore_Get(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	store := NewSessionStore(client)
	ctx := context.Background()

	// Store a test session
	sessionData := &SessionData{
		UserID:    "user123",
		Roles:     []string{"user", "admin"},
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	sessionID := "test-session"
	err := store.Store(ctx, sessionID, sessionData, time.Hour)
	if err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	tests := []struct {
		name      string
		sessionID string
		wantErr   bool
	}{
		{
			name:      "existing session",
			sessionID: sessionID,
			wantErr:   false,
		},
		{
			name:      "non-existent session",
			sessionID: "non-existent",
			wantErr:   true,
		},
		{
			name:      "empty session ID",
			sessionID: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := store.Get(ctx, tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && data == nil {
				t.Error("Get() returned nil data for valid session")
			}
			if !tt.wantErr && data.UserID != sessionData.UserID {
				t.Errorf("Get() returned wrong user ID: got %v, want %v", data.UserID, sessionData.UserID)
			}
		})
	}
}

func TestSessionStore_Update(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	store := NewSessionStore(client)
	ctx := context.Background()

	// Store initial session
	sessionData := &SessionData{
		UserID:    "user123",
		Roles:     []string{"user"},
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	sessionID := "test-session"
	err := store.Store(ctx, sessionID, sessionData, time.Hour)
	if err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	// Update session data
	updatedData := &SessionData{
		UserID:    "user123",
		Roles:     []string{"user", "admin"},
		IPAddress: "192.168.1.2",
		UserAgent: "updated-agent",
		CreatedAt: sessionData.CreatedAt,
		LastUsed:  time.Now(),
	}

	err = store.Update(ctx, sessionID, updatedData, time.Hour)
	if err != nil {
		t.Fatalf("Failed to update session: %v", err)
	}

	// Verify update
	retrieved, err := store.Get(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to get updated session: %v", err)
	}

	if len(retrieved.Roles) != 2 {
		t.Errorf("Update() roles not updated: got %v, want 2", len(retrieved.Roles))
	}
	if retrieved.IPAddress != "192.168.1.2" {
		t.Errorf("Update() IP not updated: got %v, want 192.168.1.2", retrieved.IPAddress)
	}
}

func TestSessionStore_Delete(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	store := NewSessionStore(client)
	ctx := context.Background()

	// Store a test session
	sessionData := &SessionData{
		UserID:    "user123",
		Roles:     []string{"user"},
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	sessionID := "test-session"
	err := store.Store(ctx, sessionID, sessionData, time.Hour)
	if err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	// Delete session
	err = store.Delete(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify deletion
	_, err = store.Get(ctx, sessionID)
	if err == nil {
		t.Error("Delete() session still exists after deletion")
	}
}

func TestSessionStore_Exists(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	store := NewSessionStore(client)
	ctx := context.Background()

	sessionID := "test-session"

	// Check non-existent session
	exists, err := store.Exists(ctx, sessionID)
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if exists {
		t.Error("Exists() returned true for non-existent session")
	}

	// Store session
	sessionData := &SessionData{
		UserID:    "user123",
		Roles:     []string{"user"},
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	err = store.Store(ctx, sessionID, sessionData, time.Hour)
	if err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	// Check existing session
	exists, err = store.Exists(ctx, sessionID)
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if !exists {
		t.Error("Exists() returned false for existing session")
	}
}

func TestSessionStore_Extend(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	store := NewSessionStore(client)
	ctx := context.Background()

	// Store session with short TTL
	sessionData := &SessionData{
		UserID:    "user123",
		Roles:     []string{"user"},
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	sessionID := "test-session"
	err := store.Store(ctx, sessionID, sessionData, time.Second)
	if err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	// Extend TTL
	err = store.Extend(ctx, sessionID, time.Hour)
	if err != nil {
		t.Fatalf("Failed to extend session: %v", err)
	}

	// Wait for original TTL to expire
	time.Sleep(2 * time.Second)

	// Session should still exist
	exists, err := store.Exists(ctx, sessionID)
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if !exists {
		t.Error("Extend() session expired despite extension")
	}
}

func TestSessionStore_GetUserSessions(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	store := NewSessionStore(client)
	ctx := context.Background()

	userID := "user123"

	// Store multiple sessions for the same user
	for i := 0; i < 3; i++ {
		sessionData := &SessionData{
			UserID:    userID,
			Roles:     []string{"user"},
			IPAddress: "192.168.1.1",
			UserAgent: "test-agent",
			CreatedAt: time.Now(),
			LastUsed:  time.Now(),
		}

		sessionID := fmt.Sprintf("session-%d", i)
		err := store.Store(ctx, sessionID, sessionData, time.Hour)
		if err != nil {
			t.Fatalf("Failed to store session %d: %v", i, err)
		}
	}

	// Get user sessions
	sessions, err := store.GetUserSessions(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserSessions() error: %v", err)
	}

	if len(sessions) != 3 {
		t.Errorf("GetUserSessions() returned %d sessions, want 3", len(sessions))
	}

	for _, session := range sessions {
		if session.UserID != userID {
			t.Errorf("GetUserSessions() returned session for wrong user: got %v, want %v", session.UserID, userID)
		}
	}
}

func TestSessionStore_DeleteUserSessions(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	store := NewSessionStore(client)
	ctx := context.Background()

	userID := "user123"

	// Store multiple sessions for the same user
	for i := 0; i < 3; i++ {
		sessionData := &SessionData{
			UserID:    userID,
			Roles:     []string{"user"},
			IPAddress: "192.168.1.1",
			UserAgent: "test-agent",
			CreatedAt: time.Now(),
			LastUsed:  time.Now(),
		}

		sessionID := fmt.Sprintf("session-%d", i)
		err := store.Store(ctx, sessionID, sessionData, time.Hour)
		if err != nil {
			t.Fatalf("Failed to store session %d: %v", i, err)
		}
	}

	// Delete all user sessions
	err := store.DeleteUserSessions(ctx, userID)
	if err != nil {
		t.Fatalf("DeleteUserSessions() error: %v", err)
	}

	// Verify deletion
	sessions, err := store.GetUserSessions(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserSessions() error: %v", err)
	}

	if len(sessions) != 0 {
		t.Errorf("DeleteUserSessions() left %d sessions, want 0", len(sessions))
	}
}
