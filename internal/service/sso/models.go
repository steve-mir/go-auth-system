package sso

import (
	"time"
)

// SocialAccount represents a social account linked to a user
type SocialAccount struct {
	ID           string            `json:"id"`
	UserID       string            `json:"user_id"`
	Provider     string            `json:"provider"`
	SocialID     string            `json:"social_id"`
	Email        string            `json:"email"`
	Name         string            `json:"name"`
	AccessToken  string            `json:"access_token,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// OAuthState represents OAuth state for CSRF protection
type OAuthState struct {
	State     string    `json:"state"`
	Provider  string    `json:"provider"`
	UserID    string    `json:"user_id,omitempty"` // For linking existing accounts
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// SocialAuthRequest represents a social authentication request
type SocialAuthRequest struct {
	Provider    string `json:"provider" validate:"required,oneof=google facebook github"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

// SocialAuthResponse represents a social authentication response
type SocialAuthResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

// OAuthCallbackRequest represents an OAuth callback request
type OAuthCallbackRequest struct {
	Provider string `json:"provider" validate:"required"`
	Code     string `json:"code" validate:"required"`
	State    string `json:"state" validate:"required"`
}

// LinkAccountRequest represents a request to link a social account
type LinkAccountRequest struct {
	Provider string `json:"provider" validate:"required,oneof=google facebook github"`
}

// UnlinkAccountRequest represents a request to unlink a social account
type UnlinkAccountRequest struct {
	Provider string `json:"provider" validate:"required,oneof=google facebook github"`
}

// GetLinkedAccountsResponse represents the response for getting linked accounts
type GetLinkedAccountsResponse struct {
	Accounts []LinkedAccount `json:"accounts"`
}

// ProviderConfig represents OAuth provider configuration
type ProviderConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"user_info_url"`
}

// GoogleUserInfo represents Google user information
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

// FacebookUserInfo represents Facebook user information
type FacebookUserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

// GitHubUserInfo represents GitHub user information
type GitHubUserInfo struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	Company   string `json:"company"`
	Location  string `json:"location"`
}

// GitHubEmail represents GitHub email information
type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}
