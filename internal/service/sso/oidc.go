package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCProvider provides OpenID Connect integration
type OIDCProvider struct {
	config            OIDCProviderConfig
	discoveryDocument *OIDCDiscoveryDocument
	httpClient        *http.Client
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(config OIDCProviderConfig) (*OIDCProvider, error) {
	provider := &OIDCProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Discover OIDC configuration
	if err := provider.discoverConfiguration(); err != nil {
		return nil, fmt.Errorf("failed to discover OIDC configuration: %w", err)
	}

	return provider, nil
}

// discoverConfiguration discovers OIDC provider configuration
func (p *OIDCProvider) discoverConfiguration() error {
	discoveryURL := strings.TrimSuffix(p.config.IssuerURL, "/") + "/.well-known/openid_configuration"

	req, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var discovery OIDCDiscoveryDocument
	if err := json.Unmarshal(body, &discovery); err != nil {
		return err
	}

	p.discoveryDocument = &discovery
	p.config.DiscoveryDocument = &discovery

	return nil
}

// GetAuthURL generates OIDC authorization URL
func (p *OIDCProvider) GetAuthURL(state, nonce string) string {
	params := url.Values{}
	params.Add("client_id", p.config.ClientID)
	params.Add("redirect_uri", p.config.RedirectURL)
	params.Add("scope", strings.Join(p.config.Scopes, " "))
	params.Add("response_type", "code")
	params.Add("state", state)
	if nonce != "" {
		params.Add("nonce", nonce)
	}

	return fmt.Sprintf("%s?%s", p.discoveryDocument.AuthorizationEndpoint, params.Encode())
}

// ExchangeCode exchanges authorization code for tokens
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string) (*OIDCTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", p.config.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", p.discoveryDocument.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// ValidateIDToken validates an OIDC ID token
func (p *OIDCProvider) ValidateIDToken(ctx context.Context, idToken string) (*OIDCIDTokenClaims, error) {
	// Parse token without verification first to get header
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	// Get key ID from header
	var keyID string
	if kid, ok := token.Header["kid"]; ok {
		keyID = kid.(string)
	}

	// Get signing key
	signingKey, err := p.getSigningKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Parse and validate token
	parsedToken, err := jwt.ParseWithClaims(idToken, &OIDCIDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("ID token is invalid")
	}

	claims, ok := parsedToken.Claims.(*OIDCIDTokenClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse ID token claims")
	}

	// Validate claims
	if err := p.validateIDTokenClaims(claims); err != nil {
		return nil, fmt.Errorf("ID token claims validation failed: %w", err)
	}

	return claims, nil
}

// GetUserInfo retrieves user information from UserInfo endpoint
func (p *OIDCProvider) GetUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error) {
	if p.discoveryDocument.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("UserInfo endpoint not available")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.discoveryDocument.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UserInfo request failed: %s", string(body))
	}

	var userInfo OIDCUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// RefreshToken refreshes an access token
func (p *OIDCProvider) RefreshToken(ctx context.Context, refreshToken string) (*OIDCTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, "POST", p.discoveryDocument.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: %s", string(body))
	}

	var tokenResp OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// getSigningKey retrieves the signing key for token validation
func (p *OIDCProvider) getSigningKey(ctx context.Context, keyID string) (interface{}, error) {
	// Get JWKS from the provider
	req, err := http.NewRequestWithContext(ctx, "GET", p.discoveryDocument.JWKSUri, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed: %s", string(body))
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	// Find the key with matching kid
	for _, key := range jwks.Keys {
		if kid, ok := key["kid"].(string); ok && kid == keyID {
			// For now, return the key as-is
			// In a production implementation, you would parse the JWK properly
			return key, nil
		}
	}

	return nil, fmt.Errorf("signing key not found for kid: %s", keyID)
}

// validateIDTokenClaims validates ID token claims
func (p *OIDCProvider) validateIDTokenClaims(claims *OIDCIDTokenClaims) error {
	now := time.Now().Unix()

	// Check expiration
	if claims.ExpiresAt < now {
		return fmt.Errorf("ID token has expired")
	}

	// Check issued at time (not too far in the future)
	if claims.IssuedAt > now+300 { // 5 minutes tolerance
		return fmt.Errorf("ID token issued in the future")
	}

	// Check issuer
	if claims.Issuer != p.config.IssuerURL {
		return fmt.Errorf("invalid issuer: expected %s, got %s", p.config.IssuerURL, claims.Issuer)
	}

	// Check audience
	validAudience := false
	switch aud := claims.Audience.(type) {
	case string:
		validAudience = aud == p.config.ClientID
	case []interface{}:
		for _, a := range aud {
			if audStr, ok := a.(string); ok && audStr == p.config.ClientID {
				validAudience = true
				break
			}
		}
	}

	if !validAudience {
		return fmt.Errorf("invalid audience")
	}

	return nil
}

// GenerateState generates a secure random state string
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
