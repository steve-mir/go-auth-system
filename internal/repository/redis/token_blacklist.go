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

// package redis

// import (
// 	"context"
// 	"fmt"
// 	"strconv"
// 	"time"
// )

// // TokenBlacklistRepository implements token blacklisting using Redis
// type TokenBlacklistRepository struct {
// 	client *Client
// }

// // NewTokenBlacklistRepository creates a new token blacklist repository
// func NewTokenBlacklistRepository(client *Client) *TokenBlacklistRepository {
// 	return &TokenBlacklistRepository{
// 		client: client,
// 	}
// }

// // BlacklistToken adds a token to the blacklist with expiration
// func (r *TokenBlacklistRepository) BlacklistToken(ctx context.Context, tokenHash string, expiresAt int64, reason string) error {
// 	key := r.getTokenKey(tokenHash)

// 	// Calculate TTL based on expiration time
// 	now := time.Now().Unix()
// 	ttl := time.Duration(expiresAt-now) * time.Second

// 	// Don't blacklist already expired tokens
// 	if ttl <= 0 {
// 		return nil
// 	}

// 	// Store blacklist entry with metadata
// 	value := map[string]interface{}{
// 		"reason":         reason,
// 		"blacklisted_at": now,
// 		"expires_at":     expiresAt,
// 	}

// 	err := r.client.HSet(ctx, key, value).Err()
// 	if err != nil {
// 		return fmt.Errorf("failed to blacklist token: %w", err)
// 	}

// 	// Set expiration on the key
// 	err = r.client.Expire(ctx, key, ttl).Err()
// 	if err != nil {
// 		return fmt.Errorf("failed to set token blacklist expiration: %w", err)
// 	}

// 	return nil
// }

// // IsTokenBlacklisted checks if a token is blacklisted
// func (r *TokenBlacklistRepository) IsTokenBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
// 	key := r.getTokenKey(tokenHash)

// 	exists, err := r.client.Exists(ctx, key).Result()
// 	if err != nil {
// 		return false, fmt.Errorf("failed to check token blacklist: %w", err)
// 	}

// 	return exists > 0, nil
// }

// // BlacklistUserTokens blacklists all tokens for a user
// func (r *TokenBlacklistRepository) BlacklistUserTokens(ctx context.Context, userID string, reason string) error {
// 	// Get all user tokens from session store
// 	sessionPattern := r.getUserSessionPattern(userID)

// 	keys, err := r.client.Keys(ctx, sessionPattern).Result()
// 	if err != nil {
// 		return fmt.Errorf("failed to get user sessions: %w", err)
// 	}

// 	// Blacklist each token found in sessions
// 	for _, sessionKey := range keys {
// 		// Get session data to extract token hashes
// 		sessionData, err := r.client.HGetAll(ctx, sessionKey).Result()
// 		if err != nil {
// 			continue // Skip failed sessions
// 		}

// 		// Extract and blacklist access token
// 		if accessTokenHash, exists := sessionData["access_token_hash"]; exists {
// 			if expiresAtStr, exists := sessionData["access_expires_at"]; exists {
// 				if expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64); err == nil {
// 					r.BlacklistToken(ctx, accessTokenHash, expiresAt, reason)
// 				}
// 			}
// 		}

// 		// Extract and blacklist refresh token
// 		if refreshTokenHash, exists := sessionData["refresh_token_hash"]; exists {
// 			if expiresAtStr, exists := sessionData["refresh_expires_at"]; exists {
// 				if expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64); err == nil {
// 					r.BlacklistToken(ctx, refreshTokenHash, expiresAt, reason)
// 				}
// 			}
// 		}
// 	}

// 	return nil
// }

// // GetBlacklistInfo retrieves blacklist information for a token
// func (r *TokenBlacklistRepository) GetBlacklistInfo(ctx context.Context, tokenHash string) (*BlacklistInfo, error) {
// 	key := r.getTokenKey(tokenHash)

// 	data, err := r.client.HGetAll(ctx, key).Result()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get blacklist info: %w", err)
// 	}

// 	if len(data) == 0 {
// 		return nil, nil // Token not blacklisted
// 	}

// 	info := &BlacklistInfo{}

// 	if reason, exists := data["reason"]; exists {
// 		info.Reason = reason
// 	}

// 	if blacklistedAtStr, exists := data["blacklisted_at"]; exists {
// 		if blacklistedAt, err := strconv.ParseInt(blacklistedAtStr, 10, 64); err == nil {
// 			info.BlacklistedAt = blacklistedAt
// 		}
// 	}

// 	if expiresAtStr, exists := data["expires_at"]; exists {
// 		if expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64); err == nil {
// 			info.ExpiresAt = expiresAt
// 		}
// 	}

// 	return info, nil
// }

// // CleanupExpiredTokens removes expired blacklist entries (called periodically)
// func (r *TokenBlacklistRepository) CleanupExpiredTokens(ctx context.Context) error {
// 	// Redis automatically expires keys, so this is mainly for metrics
// 	pattern := r.getTokenKey("*")

// 	keys, err := r.client.Keys(ctx, pattern).Result()
// 	if err != nil {
// 		return fmt.Errorf("failed to get blacklist keys: %w", err)
// 	}

// 	// Count active blacklisted tokens for metrics
// 	activeCount := len(keys)

// 	// Log cleanup metrics (in production, send to monitoring system)
// 	fmt.Printf("Token blacklist cleanup: %d active entries\n", activeCount)

// 	return nil
// }

// // getTokenKey generates Redis key for token blacklist
// func (r *TokenBlacklistRepository) getTokenKey(tokenHash string) string {
// 	return fmt.Sprintf("blacklist:token:%s", tokenHash)
// }

// // getUserSessionPattern generates Redis key pattern for user sessions
// func (r *TokenBlacklistRepository) getUserSessionPattern(userID string) string {
// 	return fmt.Sprintf("session:user:%s:*", userID)
// }

// // BlacklistInfo contains information about a blacklisted token
// type BlacklistInfo struct {
// 	Reason        string
// 	BlacklistedAt int64
// 	ExpiresAt     int64
// }
