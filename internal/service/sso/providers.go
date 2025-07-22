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
	"strconv"
	"strings"
	"time"
)

// BaseOAuthProvider provides common OAuth functionality
type BaseOAuthProvider struct {
	config     ProviderConfig
	httpClient *http.Client
}

// NewBaseOAuthProvider creates a new base OAuth provider
func NewBaseOAuthProvider(config ProviderConfig) *BaseOAuthProvider {
	return &BaseOAuthProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GoogleProvider implements OAuth for Google
type GoogleProvider struct {
	*BaseOAuthProvider
}

// NewGoogleProvider creates a new Google OAuth provider
func NewGoogleProvider(config ProviderConfig) *GoogleProvider {
	if config.AuthURL == "" {
		config.AuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	}
	if config.TokenURL == "" {
		config.TokenURL = "https://oauth2.googleapis.com/token"
	}
	if config.UserInfoURL == "" {
		config.UserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "email", "profile"}
	}

	return &GoogleProvider{
		BaseOAuthProvider: NewBaseOAuthProvider(config),
	}
}

// GetProviderName returns the provider name
func (g *GoogleProvider) GetProviderName() string {
	return "google"
}

// GetAuthURL generates the OAuth authorization URL
func (g *GoogleProvider) GetAuthURL(state string) string {
	params := url.Values{}
	params.Add("client_id", g.config.ClientID)
	params.Add("redirect_uri", g.config.RedirectURL)
	params.Add("scope", strings.Join(g.config.Scopes, " "))
	params.Add("response_type", "code")
	params.Add("state", state)
	params.Add("access_type", "offline")
	params.Add("prompt", "consent")

	return fmt.Sprintf("%s?%s", g.config.AuthURL, params.Encode())
}

// ExchangeCode exchanges authorization code for access token
func (g *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*OAuthToken, error) {
	data := url.Values{}
	data.Set("client_id", g.config.ClientID)
	data.Set("client_secret", g.config.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", g.config.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", g.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient.Do(req)
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

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &OAuthToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

// GetUserInfo retrieves user information using access token
func (g *GoogleProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", g.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed: %s", string(body))
	}

	var googleUser GoogleUserInfo
	if err := json.Unmarshal(body, &googleUser); err != nil {
		return nil, err
	}

	return &UserInfo{
		ID:       googleUser.ID,
		Email:    googleUser.Email,
		Name:     googleUser.Name,
		Picture:  googleUser.Picture,
		Verified: googleUser.VerifiedEmail,
		Metadata: map[string]string{
			"given_name":  googleUser.GivenName,
			"family_name": googleUser.FamilyName,
			"locale":      googleUser.Locale,
		},
	}, nil
}

// FacebookProvider implements OAuth for Facebook
type FacebookProvider struct {
	*BaseOAuthProvider
}

// NewFacebookProvider creates a new Facebook OAuth provider
func NewFacebookProvider(config ProviderConfig) *FacebookProvider {
	if config.AuthURL == "" {
		config.AuthURL = "https://www.facebook.com/v18.0/dialog/oauth"
	}
	if config.TokenURL == "" {
		config.TokenURL = "https://graph.facebook.com/v18.0/oauth/access_token"
	}
	if config.UserInfoURL == "" {
		config.UserInfoURL = "https://graph.facebook.com/v18.0/me"
	}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"email", "public_profile"}
	}

	return &FacebookProvider{
		BaseOAuthProvider: NewBaseOAuthProvider(config),
	}
}

// GetProviderName returns the provider name
func (f *FacebookProvider) GetProviderName() string {
	return "facebook"
}

// GetAuthURL generates the OAuth authorization URL
func (f *FacebookProvider) GetAuthURL(state string) string {
	params := url.Values{}
	params.Add("client_id", f.config.ClientID)
	params.Add("redirect_uri", f.config.RedirectURL)
	params.Add("scope", strings.Join(f.config.Scopes, ","))
	params.Add("response_type", "code")
	params.Add("state", state)

	return fmt.Sprintf("%s?%s", f.config.AuthURL, params.Encode())
}

// ExchangeCode exchanges authorization code for access token
func (f *FacebookProvider) ExchangeCode(ctx context.Context, code string) (*OAuthToken, error) {
	params := url.Values{}
	params.Add("client_id", f.config.ClientID)
	params.Add("client_secret", f.config.ClientSecret)
	params.Add("code", code)
	params.Add("redirect_uri", f.config.RedirectURL)

	url := fmt.Sprintf("%s?%s", f.config.TokenURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
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

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &OAuthToken{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
	}, nil
}

// GetUserInfo retrieves user information using access token
func (f *FacebookProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*UserInfo, error) {
	params := url.Values{}
	params.Add("fields", "id,email,name,picture")
	params.Add("access_token", token.AccessToken)

	url := fmt.Sprintf("%s?%s", f.config.UserInfoURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed: %s", string(body))
	}

	var facebookUser FacebookUserInfo
	if err := json.Unmarshal(body, &facebookUser); err != nil {
		return nil, err
	}

	return &UserInfo{
		ID:       facebookUser.ID,
		Email:    facebookUser.Email,
		Name:     facebookUser.Name,
		Picture:  facebookUser.Picture.Data.URL,
		Verified: true, // Facebook emails are generally verified
		Metadata: map[string]string{},
	}, nil
}

// GitHubProvider implements OAuth for GitHub
type GitHubProvider struct {
	*BaseOAuthProvider
}

// NewGitHubProvider creates a new GitHub OAuth provider
func NewGitHubProvider(config ProviderConfig) *GitHubProvider {
	if config.AuthURL == "" {
		config.AuthURL = "https://github.com/login/oauth/authorize"
	}
	if config.TokenURL == "" {
		config.TokenURL = "https://github.com/login/oauth/access_token"
	}
	if config.UserInfoURL == "" {
		config.UserInfoURL = "https://api.github.com/user"
	}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"user:email"}
	}

	return &GitHubProvider{
		BaseOAuthProvider: NewBaseOAuthProvider(config),
	}
}

// GetProviderName returns the provider name
func (gh *GitHubProvider) GetProviderName() string {
	return "github"
}

// GetAuthURL generates the OAuth authorization URL
func (gh *GitHubProvider) GetAuthURL(state string) string {
	params := url.Values{}
	params.Add("client_id", gh.config.ClientID)
	params.Add("redirect_uri", gh.config.RedirectURL)
	params.Add("scope", strings.Join(gh.config.Scopes, " "))
	params.Add("state", state)

	return fmt.Sprintf("%s?%s", gh.config.AuthURL, params.Encode())
}

// ExchangeCode exchanges authorization code for access token
func (gh *GitHubProvider) ExchangeCode(ctx context.Context, code string) (*OAuthToken, error) {
	data := url.Values{}
	data.Set("client_id", gh.config.ClientID)
	data.Set("client_secret", gh.config.ClientSecret)
	data.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, "POST", gh.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := gh.httpClient.Do(req)
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

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &OAuthToken{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   0, // GitHub tokens don't expire
	}, nil
}

// GetUserInfo retrieves user information using access token
func (gh *GitHubProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*UserInfo, error) {
	// Get user profile
	req, err := http.NewRequestWithContext(ctx, "GET", gh.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := gh.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed: %s", string(body))
	}

	var githubUser GitHubUserInfo
	if err := json.Unmarshal(body, &githubUser); err != nil {
		return nil, err
	}

	// Get user emails
	email, verified := gh.getPrimaryEmail(ctx, token)
	if email == "" {
		email = githubUser.Email
	}

	return &UserInfo{
		ID:       strconv.Itoa(githubUser.ID),
		Email:    email,
		Name:     githubUser.Name,
		Picture:  githubUser.AvatarURL,
		Verified: verified,
		Metadata: map[string]string{
			"login":    githubUser.Login,
			"company":  githubUser.Company,
			"location": githubUser.Location,
		},
	}, nil
}

// getPrimaryEmail retrieves the primary email from GitHub API
func (gh *GitHubProvider) getPrimaryEmail(ctx context.Context, token *OAuthToken) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", false
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := gh.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}

	var emails []GitHubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", false
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email, email.Verified
		}
	}

	return "", false
}

// GenerateState generates a secure random state string
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
