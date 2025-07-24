package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/middleware"
	"github.com/steve-mir/go-auth-system/internal/monitoring"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
	"github.com/steve-mir/go-auth-system/internal/service/mfa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAdminService is a mock implementation of AdminService
type MockAdminService struct {
	mock.Mock
}

func (m *MockAdminService) GetSystemInfo(ctx context.Context) (*interfaces.SystemInfo, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.SystemInfo), args.Error(1)
}

func (m *MockAdminService) GetSystemHealth(ctx context.Context) (*interfaces.SystemHealth, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.SystemHealth), args.Error(1)
}

func (m *MockAdminService) GetSystemMetrics(ctx context.Context) (*interfaces.SystemMetrics, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.SystemMetrics), args.Error(1)
}

func (m *MockAdminService) GetUserStats(ctx context.Context) (*interfaces.UserStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.UserStats), args.Error(1)
}

func (m *MockAdminService) BulkUserActions(ctx context.Context, req *interfaces.BulkUserActionRequest) (*interfaces.BulkActionResult, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.BulkActionResult), args.Error(1)
}

func (m *MockAdminService) GetAllUserSessions(ctx context.Context, req *interfaces.GetSessionsRequest) (*interfaces.GetSessionsResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.GetSessionsResponse), args.Error(1)
}

func (m *MockAdminService) DeleteUserSession(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockAdminService) GetRoleStats(ctx context.Context) (*interfaces.RoleStats, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.RoleStats), args.Error(1)
}

func (m *MockAdminService) BulkRoleAssign(ctx context.Context, req *interfaces.BulkRoleAssignRequest) (*interfaces.BulkActionResult, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.BulkActionResult), args.Error(1)
}

func (m *MockAdminService) GetAuditLogs(ctx context.Context, req *interfaces.GetAuditLogsRequest) (*interfaces.GetAuditLogsResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.GetAuditLogsResponse), args.Error(1)
}

func (m *MockAdminService) GetAuditEvents(ctx context.Context, req *interfaces.GetAuditEventsRequest) (*interfaces.GetAuditEventsResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.GetAuditEventsResponse), args.Error(1)
}

func (m *MockAdminService) GetConfiguration(ctx context.Context) (*interfaces.ConfigurationResponse, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.ConfigurationResponse), args.Error(1)
}

func (m *MockAdminService) UpdateConfiguration(ctx context.Context, req *interfaces.UpdateConfigurationRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAdminService) ReloadConfiguration(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockAdminService) GetActiveAlerts(ctx context.Context) (*interfaces.AlertsResponse, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.AlertsResponse), args.Error(1)
}

func (m *MockAdminService) CreateAlert(ctx context.Context, req *interfaces.CreateAlertRequest) (*interfaces.Alert, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.Alert), args.Error(1)
}

func (m *MockAdminService) UpdateAlert(ctx context.Context, alertID uuid.UUID, req *interfaces.UpdateAlertRequest) (*interfaces.Alert, error) {
	args := m.Called(ctx, alertID, req)
	return args.Get(0).(*interfaces.Alert), args.Error(1)
}

func (m *MockAdminService) DeleteAlert(ctx context.Context, alertID uuid.UUID) error {
	args := m.Called(ctx, alertID)
	return args.Error(0)
}

func (m *MockAdminService) GetNotificationSettings(ctx context.Context) (*interfaces.NotificationSettings, error) {
	args := m.Called(ctx)
	return args.Get(0).(*interfaces.NotificationSettings), args.Error(1)
}

func (m *MockAdminService) UpdateNotificationSettings(ctx context.Context, req *interfaces.UpdateNotificationSettingsRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

// MockAuthService is a mock implementation of AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) ValidateToken(ctx context.Context, req *auth.ValidateTokenRequest) (*auth.ValidateTokenResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*auth.ValidateTokenResponse), args.Error(1)
}

func (m *MockAuthService) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*auth.RegisterResponse), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*auth.LoginResponse), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, req *auth.LogoutRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.RefreshTokenResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*auth.RefreshTokenResponse), args.Error(1)
}

// Test setup helper
func setupTestServer() (*Server, *MockAdminService, *MockAuthService) {
	gin.SetMode(gin.TestMode)

	cfg := &config.ServerConfig{
		Host:         "localhost",
		Port:         8080,
		Environment:  "test",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	mockAdminService := &MockAdminService{}
	mockAuthService := &MockAuthService{}
	mockUserService := &MockUserService{}
	mockRoleService := &MockRoleService{}
	mockMFAService := &MockMFAService{}
	mockHealthService := &MockHealthService{}
	mockSSOService := &MockSSOService{}

	middlewareManager := &middleware.MiddlewareManager{}
	monitoringService := &monitoring.Service{}

	server := NewServer(
		cfg,
		middlewareManager,
		monitoringService,
		mockAuthService,
		mockUserService,
		mockRoleService,
		mockMFAService,
		mockAdminService,
		mockHealthService,
		mockSSOService,
	)

	return server, mockAdminService, mockAuthService
}

// Mock implementations for other services
type MockUserService struct{ mock.Mock }

func (m *MockUserService) GetProfile(ctx context.Context, userID string) (*interfaces.UserProfile, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*interfaces.UserProfile), args.Error(1)
}

func (m *MockUserService) UpdateProfile(ctx context.Context, userID string, req *interfaces.UpdateProfileRequest) (*interfaces.UserProfile, error) {
	args := m.Called(ctx, userID, req)
	return args.Get(0).(*interfaces.UserProfile), args.Error(1)
}

func (m *MockUserService) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) ListUsers(ctx context.Context, req *interfaces.ListUsersRequest) (*interfaces.ListUsersResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.ListUsersResponse), args.Error(1)
}

func (m *MockUserService) ChangePassword(ctx context.Context, userID string, req *interfaces.ChangePasswordRequest) error {
	args := m.Called(ctx, userID, req)
	return args.Error(0)
}

func (m *MockUserService) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]string), args.Error(1)
}

type MockRoleService struct{ mock.Mock }

func (m *MockRoleService) CreateRole(ctx context.Context, req interfaces.CreateRoleRequest) (*interfaces.Role, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.Role), args.Error(1)
}

func (m *MockRoleService) GetRole(ctx context.Context, roleID uuid.UUID) (*interfaces.Role, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).(*interfaces.Role), args.Error(1)
}

func (m *MockRoleService) GetRoleByName(ctx context.Context, name string) (*interfaces.Role, error) {
	args := m.Called(ctx, name)
	return args.Get(0).(*interfaces.Role), args.Error(1)
}

func (m *MockRoleService) UpdateRole(ctx context.Context, roleID uuid.UUID, req interfaces.UpdateRoleRequest) (*interfaces.Role, error) {
	args := m.Called(ctx, roleID, req)
	return args.Get(0).(*interfaces.Role), args.Error(1)
}

func (m *MockRoleService) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func (m *MockRoleService) ListRoles(ctx context.Context, req interfaces.ListRolesRequest) (*interfaces.ListRolesResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.ListRolesResponse), args.Error(1)
}

func (m *MockRoleService) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy uuid.UUID) error {
	args := m.Called(ctx, userID, roleID, assignedBy)
	return args.Error(0)
}

func (m *MockRoleService) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockRoleService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*interfaces.Role, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*interfaces.Role), args.Error(1)
}

func (m *MockRoleService) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*interfaces.UserInfo, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).([]*interfaces.UserInfo), args.Error(1)
}

func (m *MockRoleService) ValidateAccess(ctx context.Context, req interfaces.AccessRequest) (*interfaces.AccessResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*interfaces.AccessResponse), args.Error(1)
}

func (m *MockRoleService) ValidatePermission(ctx context.Context, userID uuid.UUID, permission interfaces.Permission) (bool, error) {
	args := m.Called(ctx, userID, permission)
	return args.Bool(0), args.Error(1)
}

func (m *MockRoleService) ValidatePermissions(ctx context.Context, userID uuid.UUID, permissions []interfaces.Permission) (map[string]bool, error) {
	args := m.Called(ctx, userID, permissions)
	return args.Get(0).(map[string]bool), args.Error(1)
}

func (m *MockRoleService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]interfaces.Permission, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]interfaces.Permission), args.Error(1)
}

func (m *MockRoleService) GetEffectivePermissions(ctx context.Context, userID uuid.UUID) ([]interfaces.Permission, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]interfaces.Permission), args.Error(1)
}

func (m *MockRoleService) CheckResourceAccess(ctx context.Context, userID uuid.UUID, resource string, actions []string) (map[string]bool, error) {
	args := m.Called(ctx, userID, resource, actions)
	return args.Get(0).(map[string]bool), args.Error(1)
}

func (m *MockRoleService) ValidateRoleHierarchy(ctx context.Context, userID uuid.UUID, requiredRole string) (bool, error) {
	args := m.Called(ctx, userID, requiredRole)
	return args.Bool(0), args.Error(1)
}

type MockMFAService struct{ mock.Mock }

func (m *MockMFAService) SetupTOTP(ctx context.Context, req *mfa.SetupTOTPRequest) (*mfa.SetupTOTPResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*mfa.SetupTOTPResponse), args.Error(1)
}

func (m *MockMFAService) VerifyTOTP(ctx context.Context, req *mfa.VerifyTOTPRequest) (*mfa.VerifyTOTPResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*mfa.VerifyTOTPResponse), args.Error(1)
}

func (m *MockMFAService) DisableMFA(ctx context.Context, req *mfa.DisableMFARequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

type MockHealthService struct{ mock.Mock }

func (m *MockHealthService) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	}
}

func (m *MockHealthService) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"alive"}`))
	}
}

func (m *MockHealthService) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	}
}

type MockSSOService struct{ mock.Mock }

func (m *MockSSOService) GetOAuthURL(ctx context.Context, provider string, state string) (string, error) {
	args := m.Called(ctx, provider, state)
	return args.String(0), args.Error(1)
}

func (m *MockSSOService) HandleOAuthCallback(ctx context.Context, provider, code, state string) (*OAuthResult, error) {
	args := m.Called(ctx, provider, code, state)
	return args.Get(0).(*OAuthResult), args.Error(1)
}

func (m *MockSSOService) UnlinkSocialAccount(ctx context.Context, userID string, provider string) error {
	args := m.Called(ctx, userID, provider)
	return args.Error(0)
}

func (m *MockSSOService) GetLinkedAccounts(ctx context.Context, userID string) ([]LinkedAccount, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]LinkedAccount), args.Error(1)
}

func (m *MockSSOService) GetSAMLMetadata(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSSOService) InitiateSAMLLogin(ctx context.Context, idpEntityID string, relayState string) (*SAMLAuthRequest, error) {
	args := m.Called(ctx, idpEntityID, relayState)
	return args.Get(0).(*SAMLAuthRequest), args.Error(1)
}

func (m *MockSSOService) HandleSAMLResponse(ctx context.Context, samlResponse string, relayState string) (*SAMLResult, error) {
	args := m.Called(ctx, samlResponse, relayState)
	return args.Get(0).(*SAMLResult), args.Error(1)
}

func (m *MockSSOService) GetOIDCAuthURL(ctx context.Context, provider string, state string, nonce string) (string, error) {
	args := m.Called(ctx, provider, state, nonce)
	return args.String(0), args.Error(1)
}

func (m *MockSSOService) HandleOIDCCallback(ctx context.Context, provider, code, state string) (*OIDCResult, error) {
	args := m.Called(ctx, provider, code, state)
	return args.Get(0).(*OIDCResult), args.Error(1)
}

func (m *MockSSOService) ValidateOIDCIDToken(ctx context.Context, provider, idToken string) (*OIDCIDTokenClaims, error) {
	args := m.Called(ctx, provider, idToken)
	return args.Get(0).(*OIDCIDTokenClaims), args.Error(1)
}

func (m *MockSSOService) RefreshOIDCToken(ctx context.Context, provider, refreshToken string) (*OIDCTokenResponse, error) {
	args := m.Called(ctx, provider, refreshToken)
	return args.Get(0).(*OIDCTokenResponse), args.Error(1)
}

// Test cases

func TestGetSystemInfo(t *testing.T) {
	server, mockAdminService, mockAuthService := setupTestServer()

	// Mock auth validation
	mockAuthService.On("ValidateToken", mock.Anything, mock.Anything).Return(&auth.ValidateTokenResponse{
		Valid:    true,
		UserID:   "test-user-id",
		Email:    "admin@example.com",
		Username: "admin",
		Roles:    []string{"admin"},
	}, nil)

	// Mock system info response
	expectedInfo := &interfaces.SystemInfo{
		Service: "go-auth-system",
		Version: "1.0.0",
		Build: interfaces.BuildInfo{
			GoVersion: "go1.21",
			BuildTime: time.Now(),
		},
		Runtime: interfaces.RuntimeInfo{
			Uptime:     time.Hour,
			StartTime:  time.Now().Add(-time.Hour),
			GoRoutines: 10,
		},
		Features: map[string]interface{}{
			"multi_protocol": true,
		},
		Timestamp: time.Now(),
	}

	mockAdminService.On("GetSystemInfo", mock.Anything).Return(expectedInfo, nil)

	// Create request
	req, _ := http.NewRequest("GET", "/api/v1/admin/system/info", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	server.router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.NotNil(t, response["data"])

	mockAdminService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestGetSystemHealth(t *testing.T) {
	server, mockAdminService, mockAuthService := setupTestServer()

	// Mock auth validation
	mockAuthService.On("ValidateToken", mock.Anything, mock.Anything).Return(&auth.ValidateTokenResponse{
		Valid:    true,
		UserID:   "test-user-id",
		Email:    "admin@example.com",
		Username: "admin",
		Roles:    []string{"admin"},
	}, nil)

	// Mock system health response
	expectedHealth := &interfaces.SystemHealth{
		Status: "healthy",
		Components: map[string]interfaces.ComponentHealth{
			"database": {
				Status:      "healthy",
				Message:     "Database connection is healthy",
				LastChecked: time.Now(),
			},
		},
		Timestamp: time.Now(),
	}

	mockAdminService.On("GetSystemHealth", mock.Anything).Return(expectedHealth, nil)

	// Create request
	req, _ := http.NewRequest("GET", "/api/v1/admin/system/health", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	server.router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.NotNil(t, response["data"])

	mockAdminService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestBulkUserActions(t *testing.T) {
	server, mockAdminService, mockAuthService := setupTestServer()

	// Mock auth validation
	mockAuthService.On("ValidateToken", mock.Anything, mock.Anything).Return(&auth.ValidateTokenResponse{
		Valid:    true,
		UserID:   "test-user-id",
		Email:    "admin@example.com",
		Username: "admin",
		Roles:    []string{"admin"},
	}, nil)

	// Mock bulk action response
	expectedResult := &interfaces.BulkActionResult{
		Action:  "lock",
		Total:   2,
		Success: 2,
		Failed:  0,
		Details: []interfaces.ActionDetail{
			{UserID: uuid.New(), Success: true},
			{UserID: uuid.New(), Success: true},
		},
	}

	mockAdminService.On("BulkUserActions", mock.Anything, mock.AnythingOfType("*interfaces.BulkUserActionRequest")).Return(expectedResult, nil)

	// Create request body
	requestBody := interfaces.BulkUserActionRequest{
		UserIDs: []uuid.UUID{uuid.New(), uuid.New()},
		Action:  "lock",
		Reason:  "Security violation",
	}

	body, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/api/v1/admin/users/bulk-actions", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	server.router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.NotNil(t, response["data"])

	mockAdminService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestCreateAlert(t *testing.T) {
	server, mockAdminService, mockAuthService := setupTestServer()

	// Mock auth validation
	mockAuthService.On("ValidateToken", mock.Anything, mock.Anything).Return(&auth.ValidateTokenResponse{
		Valid:    true,
		UserID:   "test-user-id",
		Email:    "admin@example.com",
		Username: "admin",
		Roles:    []string{"admin"},
	}, nil)

	// Mock create alert response
	alertID := uuid.New()
	expectedAlert := &interfaces.Alert{
		ID:         alertID,
		Type:       "security",
		Severity:   "high",
		Title:      "Test Alert",
		Message:    "This is a test alert",
		Source:     "test",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		IsActive:   true,
		IsResolved: false,
	}

	mockAdminService.On("CreateAlert", mock.Anything, mock.AnythingOfType("*interfaces.CreateAlertRequest")).Return(expectedAlert, nil)

	// Create request body
	requestBody := interfaces.CreateAlertRequest{
		Type:     "security",
		Severity: "high",
		Title:    "Test Alert",
		Message:  "This is a test alert",
		Source:   "test",
	}

	body, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/api/v1/admin/alerts", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	server.router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.NotNil(t, response["data"])

	mockAdminService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestDeleteUserSession(t *testing.T) {
	server, mockAdminService, mockAuthService := setupTestServer()

	// Mock auth validation
	mockAuthService.On("ValidateToken", mock.Anything, mock.Anything).Return(&auth.ValidateTokenResponse{
		Valid:    true,
		UserID:   "test-user-id",
		Email:    "admin@example.com",
		Username: "admin",
		Roles:    []string{"admin"},
	}, nil)

	sessionID := uuid.New()
	mockAdminService.On("DeleteUserSession", mock.Anything, sessionID).Return(nil)

	// Create request
	req, _ := http.NewRequest("DELETE", "/api/v1/admin/users/sessions/"+sessionID.String(), nil)
	req.Header.Set("Authorization", "Bearer test-token")

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	server.router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))

	mockAdminService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestUnauthorizedAccess(t *testing.T) {
	server, _, _ := setupTestServer()

	// Create request without authorization header
	req, _ := http.NewRequest("GET", "/api/v1/admin/system/info", nil)

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	server.router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["success"].(bool))
}

func TestForbiddenAccessNonAdmin(t *testing.T) {
	server, _, mockAuthService := setupTestServer()

	// Mock auth validation for non-admin user
	mockAuthService.On("ValidateToken", mock.Anything, mock.Anything).Return(&auth.ValidateTokenResponse{
		Valid:    true,
		UserID:   "test-user-id",
		Email:    "user@example.com",
		Username: "user",
		Roles:    []string{"user"}, // Non-admin role
	}, nil)

	// Create request
	req, _ := http.NewRequest("GET", "/api/v1/admin/system/info", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	server.router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["success"].(bool))

	mockAuthService.AssertExpectations(t)
}
