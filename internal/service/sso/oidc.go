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

// OIDCProvider implements OpenID Connect authentication
type OIDCProvider struct {
	config            OIDCProviderConfig
	httpClient        *http.Client
	discoveryDocument *OIDCDiscoveryDocument
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(config OIDCProviderConfig) (*OIDCProvider, error) {
	provider := &OIDCProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Discover OIDC configuration if not provided
	if config.DiscoveryDocument == nil {
		discoveryDoc, err := provider.discoverConfiguration(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to discover OIDC configuration: %w", err)
		}
		provider.discoveryDocument = discoveryDoc
	} else {
		provider.discoveryDocument = config.DiscoveryDocument
	}

	return provider, nil
}

// GetProviderName returns the provider name
func (o *OIDCProvider) GetProviderName() string {
	return o.config.Name
}

// GetAuthURL generates the OIDC authorization URL
func (o *OIDCProvider) GetAuthURL(state, nonce string) string {
	params := url.Values{}
	params.Add("client_id", o.config.ClientID)
	params.Add("redirect_uri", o.config.RedirectURL)
	params.Add("scope", strings.Join(o.config.Scopes, " "))
	params.Add("response_type", "code")
	params.Add("state", state)

	if nonce != "" {
		params.Add("nonce", nonce)
	}

	return fmt.Sprintf("%s?%s", o.discoveryDocument.AuthorizationEndpoint, params.Encode())
}

// ExchangeCode exchanges authorization code for tokens
func (o *OIDCProvider) ExchangeCode(ctx context.Context, code string) (*OIDCTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", o.config.ClientID)
	data.Set("client_secret", o.config.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", o.config.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", o.discoveryDocument.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
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

// ValidateIDToken validates and parses an OIDC ID token
func (o *OIDCProvider) ValidateIDToken(ctx context.Context, idToken string) (*OIDCIDTokenClaims, error) {
	// Parse the token without verification first to get the header
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	// Get the key ID from the token header
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("ID token missing key ID")
	}

	// Get the signing key from JWKS
	signingKey, err := o.getSigningKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Parse and validate the token with the signing key
	parsedToken, err := jwt.ParseWithClaims(idToken, &OIDCIDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return signingKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to validate ID token: %w", err)
	}

	claims, ok := parsedToken.Claims.(*OIDCIDTokenClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid ID token claims")
	}

	// Validate issuer
	if claims.Issuer != o.discoveryDocument.Issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", o.discoveryDocument.Issuer, claims.Issuer)
	}

	// Validate audience
	if !o.validateAudience(claims.Audience) {
		return nil, fmt.Errorf("invalid audience")
	}

	// Validate expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("ID token has expired")
	}

	return claims, nil
}

// GetUserInfo retrieves user information from the UserInfo endpoint
func (o *OIDCProvider) GetUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error) {
	if o.discoveryDocument.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("UserInfo endpoint not available")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", o.discoveryDocument.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
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

// RefreshToken refreshes an OIDC access token using refresh token
func (o *OIDCProvider) RefreshToken(ctx context.Context, refreshToken string) (*OIDCTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", o.config.ClientID)
	data.Set("client_secret", o.config.ClientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, "POST", o.discoveryDocument.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
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

// discoverConfiguration discovers OIDC configuration from the well-known endpoint
func (o *OIDCProvider) discoverConfiguration(ctx context.Context) (*OIDCDiscoveryDocument, error) {
	discoveryURL := strings.TrimSuffix(o.config.IssuerURL, "/") + "/.well-known/openid_configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery request failed: %s", string(body))
	}

	var discoveryDoc OIDCDiscoveryDocument
	if err := json.Unmarshal(body, &discoveryDoc); err != nil {
		return nil, err
	}

	return &discoveryDoc, nil
}

// getSigningKey retrieves the signing key from JWKS endpoint
func (o *OIDCProvider) getSigningKey(ctx context.Context, keyID string) (interface{}, error) {
	// This is a simplified implementation
	// In a production environment, you would want to cache the JWKS
	// and implement proper key rotation handling

	req, err := http.NewRequestWithContext(ctx, "GET", o.discoveryDocument.JWKSUri, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
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

	// Find the key with matching key ID
	for _, key := range jwks.Keys {
		if kid, ok := key["kid"].(string); ok && kid == keyID {
			// This is a simplified key parsing for demonstration
			// In production, you would use a proper JWKS library
			// like github.com/lestrrat-go/jwx/v2/jwk to parse RSA/ECDSA keys
			// For now, return an error to indicate incomplete implementation
			return nil, fmt.Errorf("JWKS key parsing not fully implemented - use proper JWKS library in production")
		}
	}

	return nil, fmt.Errorf("signing key not found for key ID: %s", keyID)
}

// validateAudience validates the audience claim
func (o *OIDCProvider) validateAudience(audience interface{}) bool {
	switch aud := audience.(type) {
	case string:
		return aud == o.config.ClientID
	case []interface{}:
		for _, a := range aud {
			if audStr, ok := a.(string); ok && audStr == o.config.ClientID {
				return true
			}
		}
	case []string:
		for _, a := range aud {
			if a == o.config.ClientID {
				return true
			}
		}
	}
	return false
}

// GenerateNonce generates a cryptographically secure nonce
func GenerateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
