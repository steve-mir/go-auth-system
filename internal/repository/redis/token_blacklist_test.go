package redis

import (
	"context"
	"testing"
	"time"
)

func TestTokenBlacklist_BlacklistToken(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	blacklist := NewTokenBlacklist(client)
	ctx := context.Background()

	token := "test-token-123"
	userID := "user123"
	expiresAt := time.Now().Add(time.Hour)
	reason := "user logout"
	tokenType := "access"

	tests := []struct {
		name      string
		token     string
		userID    string
		expiresAt time.Time
		reason    string
		tokenType string
		wantErr   bool
	}{
		{
			name:      "valid token",
			token:     token,
			userID:    userID,
			expiresAt: expiresAt,
			reason:    reason,
			tokenType: tokenType,
			wantErr:   false,
		},
		{
			name:      "empty token",
			token:     "",
			userID:    userID,
			expiresAt: expiresAt,
			reason:    reason,
			tokenType: tokenType,
			wantErr:   true,
		},
		{
			name:      "expired token",
			token:     "expired-token",
			userID:    userID,
			expiresAt: time.Now().Add(-time.Hour),
			reason:    reason,
			tokenType: tokenType,
			wantErr:   false, // Should not error, but won't blacklist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := blacklist.BlacklistToken(ctx, tt.token, tt.userID, tt.expiresAt, tt.reason, tt.tokenType)
			if (err != nil) != tt.wantErr {
				t.Errorf("BlacklistToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenBlacklist_IsBlacklisted(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	blacklist := NewTokenBlacklist(client)
	ctx := context.Background()

	token := "test-token-123"
	userID := "user123"
	expiresAt := time.Now().Add(time.Hour)
	reason := "user logout"
	tokenType := "access"

	// Initially not blacklisted
	isBlacklisted, _, err := blacklist.IsBlacklisted(ctx, token)
	if err != nil {
		t.Fatalf("IsBlacklisted() initial check error: %v", err)
	}
	if isBlacklisted {
		t.Error("IsBlacklisted() should not be blacklisted initially")
	}

	// Blacklist the token
	err = blacklist.BlacklistToken(ctx, token, userID, expiresAt, reason, tokenType)
	if err != nil {
		t.Fatalf("BlacklistToken() error: %v", err)
	}

	// Should now be blacklisted
	isBlacklisted, blacklistedToken, err := blacklist.IsBlacklisted(ctx, token)
	if err != nil {
		t.Fatalf("IsBlacklisted() after blacklist error: %v", err)
	}
	if !isBlacklisted {
		t.Error("IsBlacklisted() should be blacklisted after blacklisting")
	}
	if blacklistedToken == nil {
		t.Error("IsBlacklisted() should return blacklisted token data")
	}
	if blacklistedToken.UserID != userID {
		t.Errorf("IsBlacklisted() user ID = %v, want %v", blacklistedToken.UserID, userID)
	}
	if blacklistedToken.Reason != reason {
		t.Errorf("IsBlacklisted() reason = %v, want %v", blacklistedToken.Reason, reason)
	}
	if blacklistedToken.TokenType != tokenType {
		t.Errorf("IsBlacklisted() token type = %v, want %v", blacklistedToken.TokenType, tokenType)
	}
}

func TestTokenBlacklist_RemoveToken(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	blacklist := NewTokenBlacklist(client)
	ctx := context.Background()

	token := "test-token-123"
	userID := "user123"
	expiresAt := time.Now().Add(time.Hour)
	reason := "user logout"
	tokenType := "access"

	// Blacklist the token
	err := blacklist.BlacklistToken(ctx, token, userID, expiresAt, reason, tokenType)
	if err != nil {
		t.Fatalf("BlacklistToken() error: %v", err)
	}

	// Verify it's blacklisted
	isBlacklisted, _, err := blacklist.IsBlacklisted(ctx, token)
	if err != nil {
		t.Fatalf("IsBlacklisted() error: %v", err)
	}
	if !isBlacklisted {
		t.Error("IsBlacklisted() should be blacklisted before removal")
	}

	// Remove from blacklist
	err = blacklist.RemoveToken(ctx, token)
	if err != nil {
		t.Fatalf("RemoveToken() error: %v", err)
	}

	// Should no longer be blacklisted
	isBlacklisted, _, err = blacklist.IsBlacklisted(ctx, token)
	if err != nil {
		t.Fatalf("IsBlacklisted() after removal error: %v", err)
	}
	if isBlacklisted {
		t.Error("IsBlacklisted() should not be blacklisted after removal")
	}
}

func TestTokenBlacklist_GetBlacklistedTokens(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	blacklist := NewTokenBlacklist(client)
	ctx := context.Background()

	// Blacklist multiple tokens
	tokens := []string{"token1", "token2", "token3"}
	userID := "user123"
	expiresAt := time.Now().Add(time.Hour)
	reason := "test blacklist"
	tokenType := "access"

	for _, token := range tokens {
		err := blacklist.BlacklistToken(ctx, token, userID, expiresAt, reason, tokenType)
		if err != nil {
			t.Fatalf("BlacklistToken() error for %s: %v", token, err)
		}
	}

	// Get blacklisted tokens
	blacklistedTokens, err := blacklist.GetBlacklistedTokens(ctx, 10)
	if err != nil {
		t.Fatalf("GetBlacklistedTokens() error: %v", err)
	}

	if len(blacklistedTokens) != len(tokens) {
		t.Errorf("GetBlacklistedTokens() returned %d tokens, want %d", len(blacklistedTokens), len(tokens))
	}

	// Verify token data
	for _, bt := range blacklistedTokens {
		if bt.UserID != userID {
			t.Errorf("GetBlacklistedTokens() user ID = %v, want %v", bt.UserID, userID)
		}
		if bt.Reason != reason {
			t.Errorf("GetBlacklistedTokens() reason = %v, want %v", bt.Reason, reason)
		}
		if bt.TokenType != tokenType {
			t.Errorf("GetBlacklistedTokens() token type = %v, want %v", bt.TokenType, tokenType)
		}
	}
}

func TestTokenBlacklist_GetUserBlacklistedTokens(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	blacklist := NewTokenBlacklist(client)
	ctx := context.Background()

	user1ID := "user1"
	user2ID := "user2"
	expiresAt := time.Now().Add(time.Hour)
	reason := "test blacklist"
	tokenType := "access"

	// Blacklist tokens for user1
	user1Tokens := []string{"user1-token1", "user1-token2"}
	for _, token := range user1Tokens {
		err := blacklist.BlacklistToken(ctx, token, user1ID, expiresAt, reason, tokenType)
		if err != nil {
			t.Fatalf("BlacklistToken() error for user1 %s: %v", token, err)
		}
	}

	// Blacklist tokens for user2
	user2Tokens := []string{"user2-token1"}
	for _, token := range user2Tokens {
		err := blacklist.BlacklistToken(ctx, token, user2ID, expiresAt, reason, tokenType)
		if err != nil {
			t.Fatalf("BlacklistToken() error for user2 %s: %v", token, err)
		}
	}

	// Get user1 blacklisted tokens
	user1BlacklistedTokens, err := blacklist.GetUserBlacklistedTokens(ctx, user1ID)
	if err != nil {
		t.Fatalf("GetUserBlacklistedTokens() error for user1: %v", err)
	}

	if len(user1BlacklistedTokens) != len(user1Tokens) {
		t.Errorf("GetUserBlacklistedTokens() for user1 returned %d tokens, want %d", len(user1BlacklistedTokens), len(user1Tokens))
	}

	// Verify all returned tokens belong to user1
	for _, bt := range user1BlacklistedTokens {
		if bt.UserID != user1ID {
			t.Errorf("GetUserBlacklistedTokens() returned token for wrong user: got %v, want %v", bt.UserID, user1ID)
		}
	}

	// Get user2 blacklisted tokens
	user2BlacklistedTokens, err := blacklist.GetUserBlacklistedTokens(ctx, user2ID)
	if err != nil {
		t.Fatalf("GetUserBlacklistedTokens() error for user2: %v", err)
	}

	if len(user2BlacklistedTokens) != len(user2Tokens) {
		t.Errorf("GetUserBlacklistedTokens() for user2 returned %d tokens, want %d", len(user2BlacklistedTokens), len(user2Tokens))
	}
}

func TestTokenBlacklist_CleanupExpired(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	blacklist := NewTokenBlacklist(client)
	ctx := context.Background()

	userID := "user123"
	reason := "test blacklist"
	tokenType := "access"

	// Blacklist an expired token
	expiredToken := "expired-token"
	expiredAt := time.Now().Add(-time.Hour)
	err := blacklist.BlacklistToken(ctx, expiredToken, userID, expiredAt, reason, tokenType)
	if err != nil {
		t.Fatalf("BlacklistToken() error for expired token: %v", err)
	}

	// Blacklist a valid token
	validToken := "valid-token"
	validExpiresAt := time.Now().Add(time.Hour)
	err = blacklist.BlacklistToken(ctx, validToken, userID, validExpiresAt, reason, tokenType)
	if err != nil {
		t.Fatalf("BlacklistToken() error for valid token: %v", err)
	}

	// Get initial count
	initialTokens, err := blacklist.GetBlacklistedTokens(ctx, 100)
	if err != nil {
		t.Fatalf("GetBlacklistedTokens() initial error: %v", err)
	}

	// Run cleanup
	err = blacklist.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired() error: %v", err)
	}

	// Get count after cleanup
	afterTokens, err := blacklist.GetBlacklistedTokens(ctx, 100)
	if err != nil {
		t.Fatalf("GetBlacklistedTokens() after cleanup error: %v", err)
	}

	// Should have fewer tokens after cleanup
	if len(afterTokens) >= len(initialTokens) {
		t.Errorf("CleanupExpired() did not reduce token count: before %d, after %d", len(initialTokens), len(afterTokens))
	}

	// Valid token should still be blacklisted
	isBlacklisted, _, err := blacklist.IsBlacklisted(ctx, validToken)
	if err != nil {
		t.Fatalf("IsBlacklisted() for valid token after cleanup error: %v", err)
	}
	if !isBlacklisted {
		t.Error("IsBlacklisted() valid token should still be blacklisted after cleanup")
	}
}

func TestTokenBlacklist_GetStats(t *testing.T) {
	client := setupTestClient(t)
	defer client.Close()

	blacklist := NewTokenBlacklist(client)
	ctx := context.Background()

	userID := "user123"
	expiresAt := time.Now().Add(time.Hour)

	// Blacklist tokens with different types and reasons
	tokens := []struct {
		token     string
		tokenType string
		reason    string
	}{
		{"access-token-1", "access", "logout"},
		{"access-token-2", "access", "logout"},
		{"refresh-token-1", "refresh", "security"},
		{"refresh-token-2", "refresh", "logout"},
	}

	for _, tk := range tokens {
		err := blacklist.BlacklistToken(ctx, tk.token, userID, expiresAt, tk.reason, tk.tokenType)
		if err != nil {
			t.Fatalf("BlacklistToken() error for %s: %v", tk.token, err)
		}
	}

	// Get stats
	stats, err := blacklist.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}

	// Verify total count
	totalBlacklisted, ok := stats["total_blacklisted"].(int)
	if !ok {
		t.Error("GetStats() total_blacklisted should be int")
	}
	if totalBlacklisted != len(tokens) {
		t.Errorf("GetStats() total_blacklisted = %d, want %d", totalBlacklisted, len(tokens))
	}

	// Verify by type counts
	byType, ok := stats["by_type"].(map[string]int)
	if !ok {
		t.Error("GetStats() by_type should be map[string]int")
	}
	if byType["access"] != 2 {
		t.Errorf("GetStats() by_type[access] = %d, want 2", byType["access"])
	}
	if byType["refresh"] != 2 {
		t.Errorf("GetStats() by_type[refresh] = %d, want 2", byType["refresh"])
	}

	// Verify by reason counts
	byReason, ok := stats["by_reason"].(map[string]int)
	if !ok {
		t.Error("GetStats() by_reason should be map[string]int")
	}
	if byReason["logout"] != 3 {
		t.Errorf("GetStats() by_reason[logout] = %d, want 3", byReason["logout"])
	}
	if byReason["security"] != 1 {
		t.Errorf("GetStats() by_reason[security] = %d, want 1", byReason["security"])
	}
}
