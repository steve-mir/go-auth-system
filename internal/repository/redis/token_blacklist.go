package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// BlacklistedToken represents a blacklisted token
type BlacklistedToken struct {
	TokenHash     string    `json:"token_hash"`
	UserID        string    `json:"user_id,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	BlacklistedAt time.Time `json:"blacklisted_at"`
	Reason        string    `json:"reason"`
	TokenType     string    `json:"token_type"` // "access" or "refresh"
}

// TokenBlacklist handles token blacklisting operations in Redis
type TokenBlacklist struct {
	client *Client
	prefix string
}

// NewTokenBlacklist creates a new token blacklist manager
func NewTokenBlacklist(client *Client) *TokenBlacklist {
	return &TokenBlacklist{
		client: client,
		prefix: "blacklist:",
	}
}

// hashToken creates a SHA-256 hash of the token for storage
func (tb *TokenBlacklist) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// BlacklistToken adds a token to the blacklist with TTL cleanup
func (tb *TokenBlacklist) BlacklistToken(ctx context.Context, token string, userID string, expiresAt time.Time, reason string, tokenType string) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}
	if reason == "" {
		reason = "manually blacklisted"
	}
	if tokenType == "" {
		tokenType = "access"
	}

	tokenHash := tb.hashToken(token)
	key := tb.prefix + tokenHash

	blacklistedToken := &BlacklistedToken{
		TokenHash:     tokenHash,
		UserID:        userID,
		ExpiresAt:     expiresAt,
		BlacklistedAt: time.Now(),
		Reason:        reason,
		TokenType:     tokenType,
	}

	// Serialize token data
	jsonData, err := json.Marshal(blacklistedToken)
	if err != nil {
		return fmt.Errorf("failed to marshal blacklisted token: %w", err)
	}

	// Calculate TTL - blacklist should expire when token expires
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	// Store in Redis with TTL
	if err := tb.client.Set(ctx, key, jsonData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	return nil
}

// IsBlacklisted checks if a token is blacklisted
func (tb *TokenBlacklist) IsBlacklisted(ctx context.Context, token string) (bool, *BlacklistedToken, error) {
	if token == "" {
		return false, nil, fmt.Errorf("token cannot be empty")
	}

	tokenHash := tb.hashToken(token)
	key := tb.prefix + tokenHash

	jsonData, err := tb.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil, nil // Token not blacklisted
		}
		return false, nil, fmt.Errorf("failed to check token blacklist: %w", err)
	}

	var blacklistedToken BlacklistedToken
	if err := json.Unmarshal([]byte(jsonData), &blacklistedToken); err != nil {
		return false, nil, fmt.Errorf("failed to unmarshal blacklisted token: %w", err)
	}

	// Double-check expiration
	if time.Now().After(blacklistedToken.ExpiresAt) {
		// Token has expired, remove from blacklist
		tb.client.Del(ctx, key)
		return false, nil, nil
	}

	return true, &blacklistedToken, nil
}

// RemoveToken removes a token from the blacklist
func (tb *TokenBlacklist) RemoveToken(ctx context.Context, token string) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	tokenHash := tb.hashToken(token)
	key := tb.prefix + tokenHash

	if err := tb.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to remove token from blacklist: %w", err)
	}

	return nil
}

// BlacklistUserTokens blacklists all tokens for a specific user
func (tb *TokenBlacklist) BlacklistUserTokens(ctx context.Context, userID string, reason string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	if reason == "" {
		reason = "user tokens invalidated"
	}

	// Get all blacklisted tokens to find user tokens
	pattern := tb.prefix + "*"
	keys, err := tb.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get blacklist keys: %w", err)
	}

	// This is a simplified approach - in a real system, you'd want to maintain
	// a separate index of user tokens or use a different data structure
	for _, key := range keys {
		jsonData, err := tb.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var blacklistedToken BlacklistedToken
		if err := json.Unmarshal([]byte(jsonData), &blacklistedToken); err != nil {
			continue
		}

		if blacklistedToken.UserID == userID {
			// Update reason
			blacklistedToken.Reason = reason
			blacklistedToken.BlacklistedAt = time.Now()

			updatedData, err := json.Marshal(blacklistedToken)
			if err != nil {
				continue
			}

			ttl := time.Until(blacklistedToken.ExpiresAt)
			if ttl > 0 {
				tb.client.Set(ctx, key, updatedData, ttl)
			}
		}
	}

	return nil
}

// GetBlacklistedTokens returns all blacklisted tokens (for admin purposes)
func (tb *TokenBlacklist) GetBlacklistedTokens(ctx context.Context, limit int) ([]*BlacklistedToken, error) {
	if limit <= 0 {
		limit = 100 // Default limit
	}

	pattern := tb.prefix + "*"
	keys, err := tb.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get blacklist keys: %w", err)
	}

	var tokens []*BlacklistedToken
	count := 0

	for _, key := range keys {
		if count >= limit {
			break
		}

		jsonData, err := tb.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var blacklistedToken BlacklistedToken
		if err := json.Unmarshal([]byte(jsonData), &blacklistedToken); err != nil {
			continue
		}

		// Check if token is still valid (not expired)
		if time.Now().Before(blacklistedToken.ExpiresAt) {
			tokens = append(tokens, &blacklistedToken)
			count++
		} else {
			// Clean up expired token
			tb.client.Del(ctx, key)
		}
	}

	return tokens, nil
}

// GetUserBlacklistedTokens returns blacklisted tokens for a specific user
func (tb *TokenBlacklist) GetUserBlacklistedTokens(ctx context.Context, userID string) ([]*BlacklistedToken, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	pattern := tb.prefix + "*"
	keys, err := tb.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get blacklist keys: %w", err)
	}

	var userTokens []*BlacklistedToken

	for _, key := range keys {
		jsonData, err := tb.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var blacklistedToken BlacklistedToken
		if err := json.Unmarshal([]byte(jsonData), &blacklistedToken); err != nil {
			continue
		}

		if blacklistedToken.UserID == userID {
			// Check if token is still valid (not expired)
			if time.Now().Before(blacklistedToken.ExpiresAt) {
				userTokens = append(userTokens, &blacklistedToken)
			} else {
				// Clean up expired token
				tb.client.Del(ctx, key)
			}
		}
	}

	return userTokens, nil
}

// CleanupExpired removes expired tokens from the blacklist
func (tb *TokenBlacklist) CleanupExpired(ctx context.Context) error {
	pattern := tb.prefix + "*"
	keys, err := tb.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get blacklist keys: %w", err)
	}

	now := time.Now()
	cleanedCount := 0

	for _, key := range keys {
		jsonData, err := tb.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var blacklistedToken BlacklistedToken
		if err := json.Unmarshal([]byte(jsonData), &blacklistedToken); err != nil {
			// Delete invalid data
			tb.client.Del(ctx, key)
			cleanedCount++
			continue
		}

		// Delete expired tokens
		if now.After(blacklistedToken.ExpiresAt) {
			tb.client.Del(ctx, key)
			cleanedCount++
		}
	}

	return nil
}

// GetStats returns statistics about the token blacklist
func (tb *TokenBlacklist) GetStats(ctx context.Context) (map[string]interface{}, error) {
	pattern := tb.prefix + "*"
	keys, err := tb.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get blacklist keys: %w", err)
	}

	stats := map[string]interface{}{
		"total_blacklisted": len(keys),
		"by_type":           make(map[string]int),
		"by_reason":         make(map[string]int),
		"expired":           0,
	}

	now := time.Now()
	expired := 0

	for _, key := range keys {
		jsonData, err := tb.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var blacklistedToken BlacklistedToken
		if err := json.Unmarshal([]byte(jsonData), &blacklistedToken); err != nil {
			continue
		}

		if now.After(blacklistedToken.ExpiresAt) {
			expired++
		} else {
			// Count by type
			typeCount := stats["by_type"].(map[string]int)
			typeCount[blacklistedToken.TokenType]++

			// Count by reason
			reasonCount := stats["by_reason"].(map[string]int)
			reasonCount[blacklistedToken.Reason]++
		}
	}

	stats["expired"] = expired
	stats["active"] = len(keys) - expired

	return stats, nil
}
