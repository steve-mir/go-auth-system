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

// SAML 2.0 related types

// SAMLAuthRequest represents a SAML authentication request
type SAMLAuthRequest struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	RelayState  string `json:"relay_state"`
	RequestXML  string `json:"request_xml"`
	IDPEntityID string `json:"idp_entity_id"`
	CreatedAt   int64  `json:"created_at"`
}

// SAMLResult represents the result of SAML authentication
type SAMLResult struct {
	UserID       string            `json:"user_id"`
	Email        string            `json:"email"`
	Name         string            `json:"name"`
	NameID       string            `json:"name_id"`
	SessionIndex string            `json:"session_index"`
	IDPEntityID  string            `json:"idp_entity_id"`
	IsNewUser    bool              `json:"is_new_user"`
	Attributes   map[string]string `json:"attributes"`
	ExpiresAt    int64             `json:"expires_at"`
}

// SAMLAssertion represents a SAML assertion
type SAMLAssertion struct {
	ID           string            `json:"id"`
	Issuer       string            `json:"issuer"`
	Subject      string            `json:"subject"`
	NameID       string            `json:"name_id"`
	SessionIndex string            `json:"session_index"`
	NotBefore    int64             `json:"not_before"`
	NotOnOrAfter int64             `json:"not_on_or_after"`
	Audience     string            `json:"audience"`
	Attributes   map[string]string `json:"attributes"`
	Signature    string            `json:"signature"`
}

// SAMLIdentityProvider represents a SAML Identity Provider configuration
type SAMLIdentityProvider struct {
	EntityID               string `json:"entity_id"`
	SingleSignOnServiceURL string `json:"sso_service_url"`
	SingleLogoutServiceURL string `json:"slo_service_url"`
	X509Certificate        string `json:"x509_certificate"`
	NameIDFormat           string `json:"name_id_format"`
	WantAssertionsSigned   bool   `json:"want_assertions_signed"`
	WantResponseSigned     bool   `json:"want_response_signed"`
}

// SAMLServiceProvider represents SAML Service Provider metadata
type SAMLServiceProvider struct {
	EntityID                    string `json:"entity_id"`
	AssertionConsumerServiceURL string `json:"acs_url"`
	SingleLogoutServiceURL      string `json:"slo_url"`
	X509Certificate             string `json:"x509_certificate"`
	PrivateKey                  string `json:"private_key"`
	NameIDFormat                string `json:"name_id_format"`
	WantAssertionsSigned        bool   `json:"want_assertions_signed"`
	AuthnRequestsSigned         bool   `json:"authn_requests_signed"`
}

// SAMLConfig represents SAML configuration for the service
type SAMLConfig struct {
	ServiceProvider    SAMLServiceProvider             `json:"service_provider"`
	IdentityProviders  map[string]SAMLIdentityProvider `json:"identity_providers"`
	AttributeMapping   SAMLAttributeMapping            `json:"attribute_mapping"`
	SessionTimeout     int64                           `json:"session_timeout"`
	ClockSkewTolerance int64                           `json:"clock_skew_tolerance"`
	MaxAssertionAge    int64                           `json:"max_assertion_age"`
}

// SAMLAttributeMapping defines how SAML attributes map to user fields
type SAMLAttributeMapping struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	FullName  string `json:"full_name"`
	Groups    string `json:"groups"`
	Roles     string `json:"roles"`
}

// SAMLRequest represents a SAML authentication request
type SAMLRequest struct {
	IDPEntityID string `json:"idp_entity_id" validate:"required"`
	RelayState  string `json:"relay_state,omitempty"`
}

// SAMLResponse represents a SAML authentication response
type SAMLResponse struct {
	SAMLResponse string `json:"saml_response" validate:"required"`
	RelayState   string `json:"relay_state,omitempty"`
}

// SAMLMetadataResponse represents SAML metadata response
type SAMLMetadataResponse struct {
	Metadata    string `json:"metadata"`
	ContentType string `json:"content_type"`
}

// OpenID Connect related types

// OIDCDiscoveryDocument represents the OpenID Connect discovery document
type OIDCDiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSUri                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// OIDCTokenResponse represents the OIDC token response
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope,omitempty"`
}

// OIDCIDTokenClaims represents the claims in an OIDC ID token
type OIDCIDTokenClaims struct {
	Issuer            string                 `json:"iss"`
	Subject           string                 `json:"sub"`
	Audience          interface{}            `json:"aud"` // Can be string or []string
	ExpiresAt         int64                  `json:"exp"`
	IssuedAt          int64                  `json:"iat"`
	AuthTime          int64                  `json:"auth_time,omitempty"`
	Nonce             string                 `json:"nonce,omitempty"`
	Email             string                 `json:"email,omitempty"`
	EmailVerified     bool                   `json:"email_verified,omitempty"`
	Name              string                 `json:"name,omitempty"`
	GivenName         string                 `json:"given_name,omitempty"`
	FamilyName        string                 `json:"family_name,omitempty"`
	Picture           string                 `json:"picture,omitempty"`
	Locale            string                 `json:"locale,omitempty"`
	PreferredUsername string                 `json:"preferred_username,omitempty"`
	Groups            []string               `json:"groups,omitempty"`
	Roles             []string               `json:"roles,omitempty"`
	CustomClaims      map[string]interface{} `json:"-"` // For additional claims
}

// OIDCUserInfo represents user information from OIDC UserInfo endpoint
type OIDCUserInfo struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Name              string   `json:"name,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	Locale            string   `json:"locale,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Roles             []string `json:"roles,omitempty"`
}

// OIDCResult represents the result of OIDC authentication
type OIDCResult struct {
	UserID       string            `json:"user_id"`
	Email        string            `json:"email"`
	Name         string            `json:"name"`
	Subject      string            `json:"subject"`
	Provider     string            `json:"provider"`
	IsNewUser    bool              `json:"is_new_user"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	IDToken      string            `json:"id_token"`
	ExpiresAt    int64             `json:"expires_at"`
	Claims       map[string]string `json:"claims"`
}

// OIDCAuthRequest represents an OIDC authentication request
type OIDCAuthRequest struct {
	Provider    string `json:"provider" validate:"required"`
	RedirectURL string `json:"redirect_url,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
}

// OIDCCallbackRequest represents an OIDC callback request
type OIDCCallbackRequest struct {
	Provider string `json:"provider" validate:"required"`
	Code     string `json:"code" validate:"required"`
	State    string `json:"state" validate:"required"`
}

// OIDCConfig represents OIDC provider configuration
type OIDCProviderConfig struct {
	Name              string                 `json:"name"`
	IssuerURL         string                 `json:"issuer_url"`
	ClientID          string                 `json:"client_id"`
	ClientSecret      string                 `json:"client_secret"`
	RedirectURL       string                 `json:"redirect_url"`
	Scopes            []string               `json:"scopes"`
	DiscoveryDocument *OIDCDiscoveryDocument `json:"discovery_document,omitempty"`
	JWKSKeys          interface{}            `json:"jwks_keys,omitempty"` // JWKS for token validation
	ClaimsMapping     OIDCClaimsMapping      `json:"claims_mapping"`
	AllowInsecure     bool                   `json:"allow_insecure"` // For development only
}

// OIDCClaimsMapping defines how OIDC claims map to user fields
type OIDCClaimsMapping struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	FullName  string `json:"full_name"`
	Groups    string `json:"groups"`
	Roles     string `json:"roles"`
	Username  string `json:"username"`
}
