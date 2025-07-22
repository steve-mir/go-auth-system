package token

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/config"
)

// JWTService implements TokenService using JWT tokens
// NOTE: This is a simplified implementation for demonstration purposes.
// In production, use a proper JWT library like github.com/golang-jwt/jwt/v5
type JWTService struct {
	config     *config.TokenConfig
	signingKey []byte
}

// NewJWTService creates a new JWT token service
func NewJWTService(cfg *config.TokenConfig) (*JWTService, error) {
	if cfg.SigningKey == "" {
		return nil, NewInvalidKeyError("JWT signing key is required", nil)
	}

	return &JWTService{
		config:     cfg,
		signingKey: []byte(cfg.SigningKey),
	}, nil
}

// GenerateTokens creates a new access and refresh token pair
func (j *JWTService) GenerateTokens(ctx context.Context, userID string, claims TokenClaims) (*TokenPair, error) {
	now := time.Now()

	// Generate unique JTI for both tokens
	accessJTI := uuid.New().String()
	refreshJTI := uuid.New().String()

	// Create access token claims
	accessClaims := claims
	accessClaims.UserID = userID
	accessClaims.TokenType = TokenTypeAccess
	accessClaims.IssuedAt = now
	accessClaims.ExpiresAt = now.Add(j.config.AccessTTL)
	accessClaims.Issuer = j.config.Issuer
	accessClaims.Audience = j.config.Audience
	accessClaims.Subject = userID
	accessClaims.JTI = accessJTI

	// Create refresh token claims
	refreshClaims := TokenClaims{
		UserID:    userID,
		Email:     claims.Email,
		Username:  claims.Username,
		TokenType: TokenTypeRefresh,
		IssuedAt:  now,
		ExpiresAt: now.Add(j.config.RefreshTTL),
		Issuer:    j.config.Issuer,
		Audience:  j.config.Audience,
		Subject:   userID,
		JTI:       refreshJTI,
	}

	// Generate tokens
	accessToken, err := j.generateToken(accessClaims)
	if err != nil {
		return nil, NewGenerationError("failed to generate access token", err)
	}

	refreshToken, err := j.generateToken(refreshClaims)
	if err != nil {
		return nil, NewGenerationError("failed to generate refresh token", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(j.config.AccessTTL.Seconds()),
		ExpiresAt:    accessClaims.ExpiresAt,
	}, nil
}

// ValidateToken validates a token and returns its claims
func (j *JWTService) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	if tokenString == "" {
		return nil, NewFormatError("empty token", nil)
	}

	// Simple validation - check if token starts with expected prefix
	if !strings.HasPrefix(tokenString, "jwt.") {
		return nil, NewFormatError("invalid JWT format", nil)
	}

	// Extract claims from token
	claims, err := j.extractClaimsFromToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Validate expiration
	if time.Now().After(claims.ExpiresAt) {
		return nil, NewExpiredError("token has expired", nil)
	}

	// Validate signature
	if !j.validateSignature(tokenString) {
		return nil, NewSignatureError("invalid token signature", nil)
	}

	// Check if token is revoked
	revoked, err := j.IsTokenRevoked(ctx, claims.JTI)
	if err != nil {
		return nil, NewValidationError("failed to check token revocation status", err)
	}
	if revoked {
		return nil, NewRevokedError("token has been revoked", nil)
	}

	return claims, nil
}

// RefreshToken generates a new token pair using a valid refresh token
func (j *JWTService) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Validate refresh token
	claims, err := j.ValidateToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Ensure it's a refresh token
	if claims.TokenType != TokenTypeRefresh {
		return nil, NewInvalidTypeError("token is not a refresh token", nil)
	}

	// Generate new token pair
	newClaims := TokenClaims{
		UserID:   claims.UserID,
		Email:    claims.Email,
		Username: claims.Username,
		Roles:    claims.Roles,
		Metadata: claims.Metadata,
	}

	return j.GenerateTokens(ctx, claims.UserID, newClaims)
}

// RevokeToken revokes a token by adding it to blacklist
func (j *JWTService) RevokeToken(ctx context.Context, tokenString string) error {
	// Extract claims without validation to get JTI
	claims, err := j.GetTokenClaims(ctx, tokenString)
	if err != nil {
		return err
	}

	// Add to blacklist
	return j.addToBlacklist(claims.JTI, claims.ExpiresAt)
}

// IsTokenRevoked checks if a token has been revoked
func (j *JWTService) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	return j.isInBlacklist(tokenID), nil
}

// GetTokenClaims extracts claims from a token without validation
func (j *JWTService) GetTokenClaims(ctx context.Context, tokenString string) (*TokenClaims, error) {
	return j.extractClaimsFromToken(tokenString)
}

// GetTokenType returns the token service type
func (j *JWTService) GetTokenType() string {
	return "jwt"
}

// generateToken creates a JWT token with the given claims
func (j *JWTService) generateToken(claims TokenClaims) (string, error) {
	// Create claims map
	claimsMap := map[string]interface{}{
		"user_id":    claims.UserID,
		"email":      claims.Email,
		"username":   claims.Username,
		"roles":      claims.Roles,
		"token_type": string(claims.TokenType),
		"iat":        claims.IssuedAt.Unix(),
		"exp":        claims.ExpiresAt.Unix(),
		"iss":        claims.Issuer,
		"aud":        claims.Audience,
		"sub":        claims.Subject,
		"jti":        claims.JTI,
		"metadata":   claims.Metadata,
	}

	// Convert to JSON
	claimsJSON, err := json.Marshal(claimsMap)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Encode claims
	encodedClaims := base64.URLEncoding.EncodeToString(claimsJSON)

	// Generate signature
	signature := j.generateSignature(encodedClaims)

	// Create token: jwt.{claims}.{signature}
	token := fmt.Sprintf("jwt.%s.%s", encodedClaims, signature)

	return token, nil
}

// extractClaimsFromToken extracts claims from a token string
func (j *JWTService) extractClaimsFromToken(tokenString string) (*TokenClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 || parts[0] != "jwt" {
		return nil, NewFormatError("invalid token format", nil)
	}

	// Decode claims
	claimsJSON, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, NewFormatError("failed to decode claims", err)
	}

	// Parse claims
	var claimsMap map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claimsMap); err != nil {
		return nil, NewFormatError("failed to parse claims", err)
	}

	// Convert to TokenClaims
	claims := &TokenClaims{}

	if userID, ok := claimsMap["user_id"].(string); ok {
		claims.UserID = userID
	}
	if email, ok := claimsMap["email"].(string); ok {
		claims.Email = email
	}
	if username, ok := claimsMap["username"].(string); ok {
		claims.Username = username
	}
	if tokenType, ok := claimsMap["token_type"].(string); ok {
		claims.TokenType = TokenType(tokenType)
	}
	if iat, ok := claimsMap["iat"].(float64); ok {
		claims.IssuedAt = time.Unix(int64(iat), 0)
	}
	if exp, ok := claimsMap["exp"].(float64); ok {
		claims.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iss, ok := claimsMap["iss"].(string); ok {
		claims.Issuer = iss
	}
	if aud, ok := claimsMap["aud"].(string); ok {
		claims.Audience = aud
	}
	if sub, ok := claimsMap["sub"].(string); ok {
		claims.Subject = sub
	}
	if jti, ok := claimsMap["jti"].(string); ok {
		claims.JTI = jti
	}

	// Extract roles
	if rolesInterface, ok := claimsMap["roles"]; ok && rolesInterface != nil {
		if rolesSlice, ok := rolesInterface.([]interface{}); ok {
			roles := make([]string, len(rolesSlice))
			for i, role := range rolesSlice {
				if roleStr, ok := role.(string); ok {
					roles[i] = roleStr
				}
			}
			claims.Roles = roles
		}
	}

	// Extract metadata
	if metadataInterface, ok := claimsMap["metadata"]; ok && metadataInterface != nil {
		if metadataMap, ok := metadataInterface.(map[string]interface{}); ok {
			metadata := make(map[string]string)
			for k, v := range metadataMap {
				if vStr, ok := v.(string); ok {
					metadata[k] = vStr
				}
			}
			claims.Metadata = metadata
		}
	}

	return claims, nil
}

// generateSignature generates a simple signature for the token
func (j *JWTService) generateSignature(data string) string {
	// This is a simplified signature for demonstration
	// In production, use proper HMAC or RSA signing
	combined := data + string(j.signingKey)
	hash := make([]byte, 16)
	for i, b := range []byte(combined) {
		hash[i%16] ^= b
	}
	return hex.EncodeToString(hash)
}

// validateSignature validates the token signature
func (j *JWTService) validateSignature(tokenString string) bool {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false
	}

	expectedSignature := j.generateSignature(parts[1])
	return parts[2] == expectedSignature
}

// Simple in-memory blacklist for demonstration
// In production, this should use Redis
var tokenBlacklist = make(map[string]time.Time)

func (j *JWTService) addToBlacklist(tokenID string, expiresAt time.Time) error {
	tokenBlacklist[tokenID] = expiresAt
	return nil
}

func (j *JWTService) isInBlacklist(tokenID string) bool {
	expiresAt, exists := tokenBlacklist[tokenID]
	if !exists {
		return false
	}

	// Clean up expired entries
	if time.Now().After(expiresAt) {
		delete(tokenBlacklist, tokenID)
		return false
	}

	return true
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
