package token

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/config"
)

// PasetoService implements TokenService using Paseto tokens
// NOTE: This is a simplified implementation for demonstration purposes.
// In production, use a proper Paseto library like github.com/o1egl/paseto
type PasetoService struct {
	config        *config.TokenConfig
	encryptionKey []byte
}

// NewPasetoService creates a new Paseto token service
func NewPasetoService(cfg *config.TokenConfig) (*PasetoService, error) {
	if cfg.EncryptionKey == "" {
		return nil, NewInvalidKeyError("Paseto encryption key is required", nil)
	}

	// Paseto v2 requires 32-byte key
	key := []byte(cfg.EncryptionKey)
	if len(key) < 32 {
		// Pad key to 32 bytes
		paddedKey := make([]byte, 32)
		copy(paddedKey, key)
		key = paddedKey
	} else if len(key) > 32 {
		// Truncate key to 32 bytes
		key = key[:32]
	}

	return &PasetoService{
		config:        cfg,
		encryptionKey: key,
	}, nil
}

// PasetoClaims represents Paseto token claims
type PasetoClaims struct {
	UserID    string            `json:"user_id"`
	Email     string            `json:"email"`
	Username  string            `json:"username,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
	TokenType string            `json:"token_type"`
	IssuedAt  time.Time         `json:"iat"`
	ExpiresAt time.Time         `json:"exp"`
	NotBefore time.Time         `json:"nbf"`
	Issuer    string            `json:"iss"`
	Audience  string            `json:"aud"`
	Subject   string            `json:"sub"`
	JTI       string            `json:"jti"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// GenerateTokens creates a new access and refresh token pair
func (p *PasetoService) GenerateTokens(ctx context.Context, userID string, claims TokenClaims) (*TokenPair, error) {
	now := time.Now()

	// Generate unique JTI for both tokens
	accessJTI := uuid.New().String()
	refreshJTI := uuid.New().String()

	// Create access token claims
	accessClaims := PasetoClaims{
		UserID:    userID,
		Email:     claims.Email,
		Username:  claims.Username,
		Roles:     claims.Roles,
		TokenType: string(TokenTypeAccess),
		IssuedAt:  now,
		ExpiresAt: now.Add(p.config.AccessTTL),
		NotBefore: now,
		Issuer:    p.config.Issuer,
		Audience:  p.config.Audience,
		Subject:   userID,
		JTI:       accessJTI,
		Metadata:  claims.Metadata,
	}

	// Create refresh token claims
	refreshClaims := PasetoClaims{
		UserID:    userID,
		Email:     claims.Email,
		Username:  claims.Username,
		TokenType: string(TokenTypeRefresh),
		IssuedAt:  now,
		ExpiresAt: now.Add(p.config.RefreshTTL),
		NotBefore: now,
		Issuer:    p.config.Issuer,
		Audience:  p.config.Audience,
		Subject:   userID,
		JTI:       refreshJTI,
	}

	// Generate tokens
	accessToken, err := p.generateToken(accessClaims)
	if err != nil {
		return nil, NewGenerationError("failed to generate access token", err)
	}

	refreshToken, err := p.generateToken(refreshClaims)
	if err != nil {
		return nil, NewGenerationError("failed to generate refresh token", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.config.AccessTTL.Seconds()),
		ExpiresAt:    accessClaims.ExpiresAt,
	}, nil
}

// ValidateToken validates a token and returns its claims
func (p *PasetoService) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	// Decrypt and parse token
	claims, err := p.decryptToken(tokenString)
	if err != nil {
		return nil, NewValidationError("failed to decrypt token", err)
	}

	// Validate token timing
	now := time.Now()
	if now.Before(claims.NotBefore) {
		return nil, NewValidationError("token not yet valid", nil)
	}
	if now.After(claims.ExpiresAt) {
		return nil, NewExpiredError("token has expired", nil)
	}

	// Validate issuer and audience
	if p.config.Issuer != "" && claims.Issuer != p.config.Issuer {
		return nil, NewInvalidClaimError("invalid issuer", nil)
	}
	if p.config.Audience != "" && claims.Audience != p.config.Audience {
		return nil, NewInvalidClaimError("invalid audience", nil)
	}

	// Check if token is revoked
	revoked, err := p.IsTokenRevoked(ctx, claims.JTI)
	if err != nil {
		return nil, NewValidationError("failed to check token revocation status", err)
	}
	if revoked {
		return nil, NewRevokedError("token has been revoked", nil)
	}

	// Convert to TokenClaims
	tokenClaims := &TokenClaims{
		UserID:    claims.UserID,
		Email:     claims.Email,
		Username:  claims.Username,
		Roles:     claims.Roles,
		TokenType: TokenType(claims.TokenType),
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		Subject:   claims.Subject,
		JTI:       claims.JTI,
		Metadata:  claims.Metadata,
	}

	return tokenClaims, nil
}

// RefreshToken generates a new token pair using a valid refresh token
func (p *PasetoService) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Validate refresh token
	claims, err := p.ValidateToken(ctx, refreshToken)
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

	return p.GenerateTokens(ctx, claims.UserID, newClaims)
}

// RevokeToken revokes a token by adding it to blacklist
func (p *PasetoService) RevokeToken(ctx context.Context, tokenString string) error {
	// Extract claims without validation to get JTI
	claims, err := p.GetTokenClaims(ctx, tokenString)
	if err != nil {
		return err
	}

	// Add to blacklist
	return p.addToBlacklist(claims.JTI, claims.ExpiresAt)
}

// IsTokenRevoked checks if a token has been revoked
func (p *PasetoService) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	return p.isInBlacklist(tokenID), nil
}

// GetTokenClaims extracts claims from a token without validation
func (p *PasetoService) GetTokenClaims(ctx context.Context, tokenString string) (*TokenClaims, error) {
	claims, err := p.decryptToken(tokenString)
	if err != nil {
		return nil, NewFormatError("failed to decrypt token", err)
	}

	// Convert to TokenClaims
	tokenClaims := &TokenClaims{
		UserID:    claims.UserID,
		Email:     claims.Email,
		Username:  claims.Username,
		Roles:     claims.Roles,
		TokenType: TokenType(claims.TokenType),
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		Subject:   claims.Subject,
		JTI:       claims.JTI,
		Metadata:  claims.Metadata,
	}

	return tokenClaims, nil
}

// GetTokenType returns the token service type
func (p *PasetoService) GetTokenType() string {
	return "paseto"
}

// generateToken creates a Paseto token with the given claims
func (p *PasetoService) generateToken(claims PasetoClaims) (string, error) {
	// Convert claims to JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Encrypt the claims
	encryptedData, err := p.encrypt(claimsJSON)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt token: %w", err)
	}

	// Create Paseto v2.local token format
	token := fmt.Sprintf("v2.local.%s", base64.URLEncoding.EncodeToString(encryptedData))

	return token, nil
}

// decryptToken decrypts a Paseto token and returns the claims
func (p *PasetoService) decryptToken(tokenString string) (*PasetoClaims, error) {
	// Validate token format
	if !strings.HasPrefix(tokenString, "v2.local.") {
		return nil, fmt.Errorf("invalid Paseto token format")
	}

	// Extract encrypted data
	encryptedData, err := base64.URLEncoding.DecodeString(tokenString[9:]) // Remove "v2.local."
	if err != nil {
		return nil, fmt.Errorf("failed to decode token data: %w", err)
	}

	// Decrypt the data
	decryptedData, err := p.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %w", err)
	}

	// Parse claims
	var claims PasetoClaims
	if err := json.Unmarshal(decryptedData, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &claims, nil
}

// encrypt encrypts data using AES-GCM
func (p *PasetoService) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func (p *PasetoService) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Simple in-memory blacklist for demonstration
// In production, this should use Redis
var pasetoTokenBlacklist = make(map[string]time.Time)

func (p *PasetoService) addToBlacklist(tokenID string, expiresAt time.Time) error {
	pasetoTokenBlacklist[tokenID] = expiresAt
	return nil
}

func (p *PasetoService) isInBlacklist(tokenID string) bool {
	expiresAt, exists := pasetoTokenBlacklist[tokenID]
	if !exists {
		return false
	}

	// Clean up expired entries
	if time.Now().After(expiresAt) {
		delete(pasetoTokenBlacklist, tokenID)
		return false
	}

	return true
}

// generateTokenID generates a random token ID
func generateTokenID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}
