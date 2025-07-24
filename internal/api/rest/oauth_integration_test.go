package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/middleware"
)

// OAuthIntegrationTestSuite provides integration tests for OAuth functionality
type OAuthIntegrationTestSuite struct {
	suite.Suite
	server     *Server
	router     *gin.Engine
	mockSSO    *MockSSOService
	testServer *httptest.Server
}

// MockSSOService implements SSOService interface for testing
type MockSSOService struct {
	authURLs        map[string]string
	callbackResults map[string]*OAuthResult
	linkedAccounts  map[string][]LinkedAccount
	shouldFail      bool
	failureError    error
}

func NewMockSSOService() *MockSSOService {
	return &MockSSOService{
		authURLs:        make(map[string]string),
		callbackResults: make(map[string]*OAuthResult),
		linkedAccounts:  make(map[string][]LinkedAccount),
	}
}

func (m *MockSSOService) GetOAuthURL(ctx context.Context, provider string, state string) (string, error) {
	if m.shouldFail {
		return "", m.failureError
	}

	if state == "" {
		state = "test-state-123"
	}

	authURL := fmt.Sprintf("https://%s.com/oauth/authorize?client_id=test&state=%s", provider, state)
	m.authURLs[provider] = authURL
	return authURL, nil
}

func (m *MockSSOService) HandleOAuthCallback(ctx context.Context, provider, code, state string) (*OAuthResult, error) {
	if m.shouldFail {
		return nil, m.failureError
	}

	// Return predefined result or create a default one
	if result, exists := m.callbackResults[provider]; exists {
		return result, nil
	}

	return &OAuthResult{
		UserID:       "user-123",
		Email:        "test@example.com",
		Name:         "Test User",
		Provider:     provider,
		IsNewUser:    false,
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-123",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Metadata:     map[string]string{"provider_id": "123456"},
	}, nil
}

func (m *MockSSOService) UnlinkSocialAccount(ctx context.Context, userID string, provider string) error {
	if m.shouldFail {
		return m.failureError
	}

	// Remove from linked accounts
	if accounts, exists := m.linkedAccounts[userID]; exists {
		var filtered []LinkedAccount
		for _, account := range accounts {
			if account.Provider != provider {
				filtered = append(filtered, account)
			}
		}
		m.linkedAccounts[userID] = filtered
	}

	return nil
}

func (m *MockSSOService) GetLinkedAccounts(ctx context.Context, userID string) ([]LinkedAccount, error) {
	if m.shouldFail {
		return nil, m.failureError
	}

	if accounts, exists := m.linkedAccounts[userID]; exists {
		return accounts, nil
	}

	return []LinkedAccount{}, nil
}

// Implement other SSOService methods (stubs for this test)
func (m *MockSSOService) GetSAMLMetadata(ctx context.Context) ([]byte, error) {
	return []byte("<xml>metadata</xml>"), nil
}

func (m *MockSSOService) InitiateSAMLLogin(ctx context.Context, idpEntityID string, relayState string) (*SAMLAuthRequest, error) {
	return &SAMLAuthRequest{}, nil
}

func (m *MockSSOService) HandleSAMLResponse(ctx context.Context, samlResponse string, relayState string) (*SAMLResult, error) {
	return &SAMLResult{}, nil
}

func (m *MockSSOService) GetOIDCAuthURL(ctx context.Context, provider string, state string, nonce string) (string, error) {
	return "https://oidc.example.com/auth", nil
}

func (m *MockSSOService) HandleOIDCCallback(ctx context.Context, provider, code, state string) (*OIDCResult, error) {
	return &OIDCResult{}, nil
}

func (m *MockSSOService) ValidateOIDCIDToken(ctx context.Context, provider, idToken string) (*OIDCIDTokenClaims, error) {
	return &OIDCIDTokenClaims{}, nil
}

func (m *MockSSOService) RefreshOIDCToken(ctx context.Context, provider, refreshToken string) (*OIDCTokenResponse, error) {
	return &OIDCTokenResponse{}, nil
}

// SetupSuite initializes the test suite
func (suite *OAuthIntegrationTestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)

	// Create mock SSO service
	suite.mockSSO = NewMockSSOService()

	// Create server configuration
	cfg := &config.ServerConfig{
		Host:         "localhost",
		Port:         8080,
		Environment:  "test",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Create middleware manager (minimal for testing)
	middlewareConfig := middleware.DefaultConfig()
	middlewareManager := middleware.NewMiddlewareManager(middlewareConfig, nil)

	// Create server with mock services
	suite.server = NewServer(
		cfg,
		middlewareManager,
		nil,
		nil,
		nil, // authService not needed for OAuth tests
		nil, // userService not needed for OAuth tests
		nil, // roleService not needed for OAuth tests
		nil, // adminService not needed for OAuth tests
		nil, // healthService not needed for OAuth tests,
		suite.mockSSO,
	)

	suite.router = suite.server.router
	suite.testServer = httptest.NewServer(suite.router)
}

// TearDownSuite cleans up after all tests
func (suite *OAuthIntegrationTestSuite) TearDownSuite() {
	if suite.testServer != nil {
		suite.testServer.Close()
	}
}

// SetupTest runs before each test
func (suite *OAuthIntegrationTestSuite) SetupTest() {
	// Reset mock state
	suite.mockSSO.authURLs = make(map[string]string)
	suite.mockSSO.callbackResults = make(map[string]*OAuthResult)
	suite.mockSSO.linkedAccounts = make(map[string][]LinkedAccount)
	suite.mockSSO.shouldFail = false
	suite.mockSSO.failureError = nil
}

// TestOAuthInitiate tests OAuth initiation for different providers
func (suite *OAuthIntegrationTestSuite) TestOAuthInitiate() {
	testCases := []struct {
		name           string
		provider       string
		expectedStatus int
		expectAuthURL  bool
	}{
		{
			name:           "Google OAuth initiation",
			provider:       "google",
			expectedStatus: http.StatusOK,
			expectAuthURL:  true,
		},
		{
			name:           "Facebook OAuth initiation",
			provider:       "facebook",
			expectedStatus: http.StatusOK,
			expectAuthURL:  true,
		},
		{
			name:           "GitHub OAuth initiation",
			provider:       "github",
			expectedStatus: http.StatusOK,
			expectAuthURL:  true,
		},
		{
			name:           "Invalid provider",
			provider:       "invalid",
			expectedStatus: http.StatusBadRequest,
			expectAuthURL:  false,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Make request
			req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/oauth/%s", tc.provider), nil)
			require.NoError(suite.T(), err)

			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			// Check status code
			assert.Equal(suite.T(), tc.expectedStatus, w.Code)

			if tc.expectAuthURL {
				// Parse response
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)

				// Check response structure
				assert.True(suite.T(), response["success"].(bool))
				assert.Contains(suite.T(), response["data"], "auth_url")
				assert.Contains(suite.T(), response["data"], "provider")

				data := response["data"].(map[string]interface{})
				assert.Equal(suite.T(), tc.provider, data["provider"])
				assert.Contains(suite.T(), data["auth_url"].(string), tc.provider)
			}
		})
	}
}

// TestOAuthCallback tests OAuth callback handling
func (suite *OAuthIntegrationTestSuite) TestOAuthCallback() {
	testCases := []struct {
		name           string
		provider       string
		code           string
		state          string
		setupMock      func()
		expectedStatus int
		expectUserData bool
	}{
		{
			name:     "Successful Google callback",
			provider: "google",
			code:     "auth-code-123",
			state:    "state-123",
			setupMock: func() {
				suite.mockSSO.callbackResults["google"] = &OAuthResult{
					UserID:       "google-user-123",
					Email:        "user@gmail.com",
					Name:         "Google User",
					Provider:     "google",
					IsNewUser:    true,
					AccessToken:  "google-access-token",
					RefreshToken: "google-refresh-token",
					ExpiresAt:    time.Now().Add(time.Hour).Unix(),
					Metadata:     map[string]string{"google_id": "123456789"},
				}
			},
			expectedStatus: http.StatusOK,
			expectUserData: true,
		},
		{
			name:     "Successful Facebook callback",
			provider: "facebook",
			code:     "fb-auth-code-123",
			state:    "fb-state-123",
			setupMock: func() {
				suite.mockSSO.callbackResults["facebook"] = &OAuthResult{
					UserID:       "fb-user-123",
					Email:        "user@facebook.com",
					Name:         "Facebook User",
					Provider:     "facebook",
					IsNewUser:    false,
					AccessToken:  "fb-access-token",
					RefreshToken: "fb-refresh-token",
					ExpiresAt:    time.Now().Add(time.Hour).Unix(),
					Metadata:     map[string]string{"facebook_id": "987654321"},
				}
			},
			expectedStatus: http.StatusOK,
			expectUserData: true,
		},
		{
			name:           "Missing code parameter",
			provider:       "google",
			code:           "",
			state:          "state-123",
			setupMock:      func() {},
			expectedStatus: http.StatusBadRequest,
			expectUserData: false,
		},
		{
			name:           "Missing state parameter",
			provider:       "google",
			code:           "auth-code-123",
			state:          "",
			setupMock:      func() {},
			expectedStatus: http.StatusBadRequest,
			expectUserData: false,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Setup mock
			tc.setupMock()

			// Build URL with query parameters
			u, err := url.Parse(fmt.Sprintf("/api/v1/oauth/%s/callback", tc.provider))
			require.NoError(suite.T(), err)

			q := u.Query()
			if tc.code != "" {
				q.Set("code", tc.code)
			}
			if tc.state != "" {
				q.Set("state", tc.state)
			}
			u.RawQuery = q.Encode()

			// Make request
			req, err := http.NewRequest("GET", u.String(), nil)
			require.NoError(suite.T(), err)

			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			// Check status code
			assert.Equal(suite.T(), tc.expectedStatus, w.Code)

			if tc.expectUserData {
				// Parse response
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(suite.T(), err)

				// Check response structure
				assert.True(suite.T(), response["success"].(bool))

				data := response["data"].(map[string]interface{})
				assert.Contains(suite.T(), data, "user_id")
				assert.Contains(suite.T(), data, "email")
				assert.Contains(suite.T(), data, "name")
				assert.Contains(suite.T(), data, "provider")
				assert.Contains(suite.T(), data, "is_new_user")
				assert.Contains(suite.T(), data, "access_token")

				assert.Equal(suite.T(), tc.provider, data["provider"])
			}
		})
	}
}

// TestOAuthLinkAccount tests linking social accounts (requires authentication)
func (suite *OAuthIntegrationTestSuite) TestOAuthLinkAccount() {
	// This test would require authentication middleware to be properly set up
	// For now, we'll test the basic structure

	req, err := http.NewRequest("POST", "/api/v1/oauth/link/google", nil)
	require.NoError(suite.T(), err)

	// Add mock authorization header (this would normally be validated by auth middleware)
	req.Header.Set("Authorization", "Bearer mock-token")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	// Without proper auth middleware setup, this will return unauthorized
	// In a real integration test, we'd set up the full auth flow
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

// TestOAuthUnlinkAccount tests unlinking social accounts
func (suite *OAuthIntegrationTestSuite) TestOAuthUnlinkAccount() {
	// Similar to link account, this requires authentication
	req, err := http.NewRequest("DELETE", "/api/v1/oauth/unlink/google", nil)
	require.NoError(suite.T(), err)

	req.Header.Set("Authorization", "Bearer mock-token")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	// Without proper auth middleware setup, this will return unauthorized
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

// TestOAuthGetLinkedAccounts tests retrieving linked accounts
func (suite *OAuthIntegrationTestSuite) TestOAuthGetLinkedAccounts() {
	req, err := http.NewRequest("GET", "/api/v1/oauth/linked", nil)
	require.NoError(suite.T(), err)

	req.Header.Set("Authorization", "Bearer mock-token")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	// Without proper auth middleware setup, this will return unauthorized
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

// TestOAuthErrorHandling tests error scenarios
func (suite *OAuthIntegrationTestSuite) TestOAuthErrorHandling() {
	suite.Run("SSO service failure", func() {
		// Setup mock to fail
		suite.mockSSO.shouldFail = true
		suite.mockSSO.failureError = fmt.Errorf("SSO service unavailable")

		req, err := http.NewRequest("GET", "/api/v1/oauth/google", nil)
		require.NoError(suite.T(), err)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		// Should return internal server error
		assert.Equal(suite.T(), http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)

		assert.False(suite.T(), response["success"].(bool))
		assert.Contains(suite.T(), response, "error")
	})
}

// TestSAMLEndpoints tests SAML endpoints (basic structure)
func (suite *OAuthIntegrationTestSuite) TestSAMLEndpoints() {
	suite.Run("SAML metadata", func() {
		req, err := http.NewRequest("GET", "/api/v1/saml/metadata", nil)
		require.NoError(suite.T(), err)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)
		assert.Equal(suite.T(), "application/samlmetadata+xml", w.Header().Get("Content-Type"))
	})

	suite.Run("SAML login initiation", func() {
		reqBody := map[string]string{
			"idp_entity_id": "https://idp.example.com",
			"relay_state":   "test-relay-state",
		}

		jsonBody, err := json.Marshal(reqBody)
		require.NoError(suite.T(), err)

		req, err := http.NewRequest("POST", "/api/v1/saml/login", bytes.NewBuffer(jsonBody))
		require.NoError(suite.T(), err)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)
	})
}

// TestOIDCEndpoints tests OIDC endpoints (basic structure)
func (suite *OAuthIntegrationTestSuite) TestOIDCEndpoints() {
	suite.Run("OIDC initiation", func() {
		req, err := http.NewRequest("GET", "/api/v1/oidc/oidc", nil)
		require.NoError(suite.T(), err)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)

		assert.True(suite.T(), response["success"].(bool))
		assert.Contains(suite.T(), response["data"], "auth_url")
	})
}

// TestProviderValidation tests provider validation logic
func (suite *OAuthIntegrationTestSuite) TestProviderValidation() {
	validProviders := []string{"google", "facebook", "github"}
	invalidProviders := []string{"twitter", "linkedin", "invalid", ""}

	for _, provider := range validProviders {
		suite.Run(fmt.Sprintf("Valid provider: %s", provider), func() {
			req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/oauth/%s", provider), nil)
			require.NoError(suite.T(), err)

			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(suite.T(), http.StatusOK, w.Code)
		})
	}

	for _, provider := range invalidProviders {
		suite.Run(fmt.Sprintf("Invalid provider: %s", provider), func() {
			req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/oauth/%s", provider), nil)
			require.NoError(suite.T(), err)

			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
		})
	}
}

// TestResponseFormat tests that all responses follow the expected format
func (suite *OAuthIntegrationTestSuite) TestResponseFormat() {
	suite.Run("Success response format", func() {
		req, err := http.NewRequest("GET", "/api/v1/oauth/google", nil)
		require.NoError(suite.T(), err)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)

		// Check standard response structure
		assert.Contains(suite.T(), response, "success")
		assert.Contains(suite.T(), response, "data")
		assert.Contains(suite.T(), response, "timestamp")
		assert.True(suite.T(), response["success"].(bool))
	})

	suite.Run("Error response format", func() {
		req, err := http.NewRequest("GET", "/api/v1/oauth/invalid", nil)
		require.NoError(suite.T(), err)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)

		// Check error response structure
		assert.Contains(suite.T(), response, "success")
		assert.Contains(suite.T(), response, "error")
		assert.Contains(suite.T(), response, "timestamp")
		assert.False(suite.T(), response["success"].(bool))

		errorData := response["error"].(map[string]interface{})
		assert.Contains(suite.T(), errorData, "code")
		assert.Contains(suite.T(), errorData, "message")
	})
}

// Run the test suite
func TestOAuthIntegrationSuite(t *testing.T) {
	suite.Run(t, new(OAuthIntegrationTestSuite))
}
