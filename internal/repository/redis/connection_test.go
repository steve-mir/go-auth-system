package redis

import (
	"context"
	"testing"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.RedisConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "valid config",
			config: &config.RedisConfig{
				Host:         "localhost",
				Port:         6379,
				DB:           0,
				PoolSize:     10,
				MinIdleConns: 2,
				DialTimeout:  5 * time.Second,
				ReadTimeout:  3 * time.Second,
				WriteTimeout: 3 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if client != nil {
				defer client.Close()
			}
		})
	}
}

func TestClient_Health(t *testing.T) {
	cfg := &config.RedisConfig{
		Host:         "localhost",
		Port:         6379,
		DB:           0,
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
	defer client.Close()

	ctx := context.Background()
	if err := client.Health(ctx); err != nil {
		t.Errorf("Health() error = %v", err)
	}
}

func TestClient_GetStats(t *testing.T) {
	cfg := &config.RedisConfig{
		Host:         "localhost",
		Port:         6379,
		DB:           0,
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
	defer client.Close()

	stats := client.GetStats()
	if stats == nil {
		t.Error("GetStats() returned nil")
	}
}
