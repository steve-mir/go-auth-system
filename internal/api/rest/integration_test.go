package rest

// import (
// 	"bytes"
// 	"context"
// 	"encoding/json"
// 	"net/http"
// 	"net/http/httptest"
// 	"testing"
// 	"time"

// 	"github.com/gin-gonic/gin"
// 	"github.com/steve-mir/go-auth-system/internal/config"
// 	"github.com/steve-mir/go-auth-system/internal/health"
// 	"github.com/steve-mir/go-auth-system/internal/middleware"
// 	"github.com/steve-mir/go-auth-system/internal/service/auth"
// 	"github.com/steve-mir/go-auth-system/internal/service/role"
// 	"github.com/steve-mir/go-auth-system/internal/service/user"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// 	"github.com/stretchr/testify/suite"
// )

// // MockAuthService is a mock implementation of auth.AuthService
// type MockAuthService struct {
// 	mock.Mock
// }

// func (m *MockAuthService) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*auth.RegisterResponse), args.Error(1)
// }

// func (m *MockAuthService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*auth.LoginResponse), args.Error(1)
// }

// func (m *MockAuthService) Logout(ctx context.Context, req *auth.LogoutRequest) error {
// 	args := m.Called(ctx, req)
// 	return args.Error(0)
// }

// func (m *MockAuthService) RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.TokenResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*auth.TokenResponse), args.Error(1)
// }

// func (m *MockAuthService) ValidateToken(ctx context.Context, req *auth.ValidateTokenRequest) (*auth.ValidateTokenResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*auth.ValidateTokenResponse), args.Error(1)
// }

// func (m *MockAuthService) GetUserProfile(ctx context.Context, token string) (*auth.UserProfile, error) {
// 	args := m.Called(ctx, token)
// 	return args.Get(0).(*auth.UserProfile), args.Error(1)
// }

// func (m *MockAuthService) GetUserSessions(ctx context.Context, userID string) ([]*auth.SessionInfo, error) {
// 	args := m.Called(ctx, userID)
// 	return args.Get(0).([]*auth.SessionInfo), args.Error(1)
// }

// func (m *MockAuthService) RevokeUserSessions(ctx context.Context, userID string) error {
// 	args := m.Called(ctx, userID)
// 	return args.Error(0)
// }

// func (m *MockAuthService) RevokeSession(ctx context.Context, sessionID string) error {
// 	args := m.Called(ctx, sessionID)
// 	return args.Error(0)
// }

// // MockUserService is a mock implementation of user.UserService
// type MockUserService struct {
// 	mock.Mock
// }

// func (m *MockUserService) GetProfile(ctx context.Context, userID string) (*user.UserProfile, error) {
// 	args := m.Called(ctx, userID)
// 	return args.Get(0).(*user.UserProfile), args.Error(1)
// }

// func (m *MockUserService) UpdateProfile(ctx context.Context, userID string, req *user.UpdateProfileRequest) (*user.UserProfile, error) {
// 	args := m.Called(ctx, userID, req)
// 	return args.Get(0).(*user.UserProfile), args.Error(1)
// }

// func (m *MockUserService) DeleteUser(ctx context.Context, userID string) error {
// 	args := m.Called(ctx, userID)
// 	return args.Error(0)
// }

// func (m *MockUserService) ListUsers(ctx context.Context, req *user.ListUsersRequest) (*user.ListUsersResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*user.ListUsersResponse), args.Error(1)
// }

// func (m *MockUserService) ChangePassword(ctx context.Context, userID string, req *user.ChangePasswordRequest) error {
// 	args := m.Called(ctx, userID, req)
// 	return args.Error(0)
// }

// func (m *MockUserService) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
// 	args := m.Called(ctx, userID)
// 	return args.Get(0).([]string), args.Error(1)
// }

// // MockRoleService is a mock implementation of role.Service
// type MockRoleService struct {
// 	mock.Mock
// }

// func (m *MockRoleService) CreateRole(ctx context.Context, req role.CreateRoleRequest) (*role.Role, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*role.Role), args.Error(1)
// }

// func (m *MockRoleService) GetRole(ctx context.Context, roleID interface{}) (*role.Role, error) {
// 	args := m.Called(ctx, roleID)
// 	return args.Get(0).(*role.Role), args.Error(1)
// }

// func (m *MockRoleService) GetRoleByName(ctx context.Context, name string) (*role.Role, error) {
// 	args := m.Called(ctx, name)
// 	return args.Get(0).(*role.Role), args.Error(1)
// }

// func (m *MockRoleService) UpdateRole(ctx context.Context, roleID interface{}, req role.UpdateRoleRequest) (*role.Role, error) {
// 	args := m.Called(ctx, roleID, req)
// 	return args.Get(0).(*role.Role), args.Error(1)
// }

// func (m *MockRoleService) DeleteRole(ctx context.Context, roleID interface{}) error {
// 	args := m.Called(ctx, roleID)
// 	return args.Error(0)
// }

// func (m *MockRoleService) ListRoles(ctx context.Context, req role.ListRolesRequest) (*role.ListRolesResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*role.ListRolesResponse), args.Error(1)
// }

// func (m *MockRoleService) AssignRoleToUser(ctx context.Context, userID, roleID, assignedBy interface{}) error {
// 	args := m.Called(ctx, userID, roleID, assignedBy)
// 	return args.Error(0)
// }

// func (m *MockRoleService) RemoveRoleFromUser(ctx context.Context, userID, roleID interface{}) error {
// 	args := m.Called(ctx, userID, roleID)
// 	return args.Error(0)
// }

// func (m *MockRoleService) GetUserRoles(ctx context.Context, userID interface{}) ([]*role.Role, error) {
// 	args := m.Called(ctx, userID)
// 	return args.Get(0).([]*role.Role), args.Error(1)
// }

// func (m *MockRoleService) GetRoleUsers(ctx context.Context, roleID interface{}) ([]*role.UserInfo, error) {
// 	args := m.Called(ctx, roleID)
// 	return args.Get(0).([]*role.UserInfo), args.Error(1)
// }

// func (m *MockRoleService) ValidatePermission(ctx context.Context, userID interface{}, permission role.Permission) (bool, error) {
// 	args := m.Called(ctx, userID, permission)
// 	return args.Get(0).(bool), args.Error(1)
// }

// func (m *MockRoleService) ValidatePermissions(ctx context.Context, userID interface{}, permissions []role.Permission) (map[string]bool, error) {
// 	args := m.Called(ctx, userID, permissions)
// 	return args.Get(0).(map[string]bool), args.Error(1)
// }

// func (m *MockRoleService) GetUserPermissions(ctx context.Context, userID interface{}) ([]role.Permission, error) {
// 	args := m.Called(ctx, userID)
// 	return args.Get(0).([]role.Permission), args.Error(1)
// }

// func (m *MockRoleService) ValidateAccess(ctx context.Context, req role.AccessRequest) (*role.AccessResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*role.AccessResponse), args.Error(1)
// }

// func (m *MockRoleService) GetEffectivePermissions(ctx context.Context, userID interface{}) ([]role.Permission, error) {
// 	args := m.Called(ctx, userID)
// 	return args.Get(0).([]role.Permission), args.Error(1)
// }

// func (m *MockRoleService) CheckResourceAccess(ctx context.Context, userID interface{}, resource string, actions []string) (map[string]bool, error) {
// 	args := m.Called(ctx, userID, resource, actions)
// 	return args.Get(0).(map[string]bool), args.Error(1)
// }

// func (m *MockRoleService) ValidateRoleHierarchy(ctx context.Context, userID interface{}, requiredRole string) (bool, error) {
// 	args := m.Called(ctx, userID, requiredRole)
// 	return args.Get(0).(bool), args.Error(1)
// }

// // RestAPITestSuite is the test suite for REST API
// type RestAPITestSuite struct {
// 	suite.Suite
// 	server      *Server
// 	authService *MockAuthService
// 	userService *MockUserService
// 	roleService *MockRoleService
// }

// // SetupSuite sets up the test suite
// func (suite *RestAPITestSuite) SetupSuite() {
// 	gin.SetMode(gin.TestMode)

// 	// Create mock services
// 	suite.authService = &MockAuthService{}
// 	suite.userService = &MockUserService{}
// 	suite.roleService = &MockRoleService{}

// 	// Create server config
// 	cfg := &config.ServerConfig{
// 		Host:         "localhost",
// 		Port:         8080,
// 		Environment:  "test",
// 		ReadTimeout:  30 * time.Second,
// 		WriteTimeout: 30 * time.Second,
// 		IdleTimeout:  60 * time.Second,
// 	}

// 	// Create middleware manager with default config
// 	middlewareManager := middleware.NewMiddlewareManager(middleware.DefaultConfig(), nil)
// 	healthService := health.NewService()
// 	// Create server
// 	suite.server = NewServer(
// 		cfg,
// 		middlewareManager,
// 		suite.authService,
// 		suite.userService,
// 		suite.roleService,
// 		suite.server.adminService,
// 		healthService,
// 	)
// }

// // TearDownTest cleans up after each test
// func (suite *RestAPITestSuite) TearDownTest() {
// 	suite.authService.ExpectedCalls = nil
// 	suite.userService.ExpectedCalls = nil
// 	suite.roleService.ExpectedCalls = nil
// }

// // TestHealthEndpoints tests health check endpoints
// func (suite *RestAPITestSuite) TestHealthEndpoints() {
// 	tests := []struct {
// 		name           string
// 		endpoint       string
// 		expectedStatus int
// 	}{
// 		{"Root endpoint", "/", http.StatusOK},
// 		{"Health endpoint", "/health", http.StatusOK},
// 		{"Liveness endpoint", "/health/live", http.StatusOK},
// 		{"Readiness endpoint", "/health/ready", http.StatusOK},
// 	}

// 	for _, tt := range tests {
// 		suite.Run(tt.name, func() {
// 			req, _ := http.NewRequest("GET", tt.endpoint, nil)
// 			w := httptest.NewRecorder()
// 			suite.server.router.ServeHTTP(w, req)

// 			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

// 			var response map[string]interface{}
// 			err := json.Unmarshal(w.Body.Bytes(), &response)
// 			assert.NoError(suite.T(), err)
// 		})
// 	}
// }

// // TestAuthEndpoints tests authentication endpoints
// func (suite *RestAPITestSuite) TestAuthEndpoints() {
// 	suite.Run("Register endpoint", func() {
// 		// Mock the auth service
// 		suite.authService.On("Register", mock.Anything, mock.AnythingOfType("*auth.RegisterRequest")).Return(
// 			&auth.RegisterResponse{
// 				UserID:    "user-123",
// 				Email:     "test@example.com",
// 				Username:  "testuser",
// 				CreatedAt: time.Now(),
// 				Message:   "User registered successfully",
// 			}, nil)

// 		reqBody := map[string]interface{}{
// 			"email":    "test@example.com",
// 			"username": "testuser",
// 			"password": "password123",
// 		}
// 		body, _ := json.Marshal(reqBody)

// 		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
// 		req.Header.Set("Content-Type", "application/json")
// 		w := httptest.NewRecorder()
// 		suite.server.router.ServeHTTP(w, req)

// 		assert.Equal(suite.T(), http.StatusCreated, w.Code)

// 		var response APIResponse
// 		err := json.Unmarshal(w.Body.Bytes(), &response)
// 		assert.NoError(suite.T(), err)
// 		assert.True(suite.T(), response.Success)
// 	})

// 	suite.Run("Login endpoint", func() {
// 		// Mock the auth service
// 		suite.authService.On("Login", mock.Anything, mock.AnythingOfType("*auth.LoginRequest")).Return(
// 			&auth.LoginResponse{
// 				UserID:       "user-123",
// 				Email:        "test@example.com",
// 				Username:     "testuser",
// 				AccessToken:  "access-token",
// 				RefreshToken: "refresh-token",
// 				TokenType:    "Bearer",
// 				ExpiresIn:    3600,
// 				ExpiresAt:    time.Now().Add(time.Hour),
// 			}, nil)

// 		reqBody := map[string]interface{}{
// 			"email":    "test@example.com",
// 			"password": "password123",
// 		}
// 		body, _ := json.Marshal(reqBody)

// 		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
// 		req.Header.Set("Content-Type", "application/json")
// 		w := httptest.NewRecorder()
// 		suite.server.router.ServeHTTP(w, req)

// 		assert.Equal(suite.T(), http.StatusOK, w.Code)

// 		var response APIResponse
// 		err := json.Unmarshal(w.Body.Bytes(), &response)
// 		assert.NoError(suite.T(), err)
// 		assert.True(suite.T(), response.Success)
// 	})
// }

// // TestValidationErrors tests request validation
// func (suite *RestAPITestSuite) TestValidationErrors() {
// 	suite.Run("Invalid registration request", func() {
// 		reqBody := map[string]interface{}{
// 			"email":    "invalid-email",
// 			"password": "123", // Too short
// 		}
// 		body, _ := json.Marshal(reqBody)

// 		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
// 		req.Header.Set("Content-Type", "application/json")
// 		w := httptest.NewRecorder()
// 		suite.server.router.ServeHTTP(w, req)

// 		assert.Equal(suite.T(), http.StatusBadRequest, w.Code)

// 		var response APIResponse
// 		err := json.Unmarshal(w.Body.Bytes(), &response)
// 		assert.NoError(suite.T(), err)
// 		assert.False(suite.T(), response.Success)
// 		assert.Equal(suite.T(), "VALIDATION_ERROR", response.Error.Code)
// 	})
// }

// // TestAuthenticationMiddleware tests authentication middleware
// func (suite *RestAPITestSuite) TestAuthenticationMiddleware() {
// 	suite.Run("Missing authorization header", func() {
// 		req, _ := http.NewRequest("GET", "/api/v1/users/profile", nil)
// 		w := httptest.NewRecorder()
// 		suite.server.router.ServeHTTP(w, req)

// 		assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
// 	})

// 	suite.Run("Invalid token format", func() {
// 		req, _ := http.NewRequest("GET", "/api/v1/users/profile", nil)
// 		req.Header.Set("Authorization", "InvalidFormat token")
// 		w := httptest.NewRecorder()
// 		suite.server.router.ServeHTTP(w, req)

// 		assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
// 	})

// 	suite.Run("Valid token", func() {
// 		// Mock token validation
// 		suite.authService.On("ValidateToken", mock.Anything, mock.AnythingOfType("*auth.ValidateTokenRequest")).Return(
// 			&auth.ValidateTokenResponse{
// 				Valid:    true,
// 				UserID:   "user-123",
// 				Email:    "test@example.com",
// 				Username: "testuser",
// 				Roles:    []string{"user"},
// 			}, nil)

// 		// Mock user profile retrieval
// 		suite.userService.On("GetProfile", mock.Anything, "user-123").Return(
// 			&user.UserProfile{
// 				ID:       "user-123",
// 				Email:    "test@example.com",
// 				Username: "testuser",
// 			}, nil)

// 		req, _ := http.NewRequest("GET", "/api/v1/users/profile", nil)
// 		req.Header.Set("Authorization", "Bearer valid-token")
// 		w := httptest.NewRecorder()
// 		suite.server.router.ServeHTTP(w, req)

// 		assert.Equal(suite.T(), http.StatusOK, w.Code)
// 	})
// }

// // TestPagination tests pagination functionality
// func (suite *RestAPITestSuite) TestPagination() {
// 	suite.Run("Valid pagination parameters", func() {
// 		// Mock token validation for admin user
// 		suite.authService.On("ValidateToken", mock.Anything, mock.AnythingOfType("*auth.ValidateTokenRequest")).Return(
// 			&auth.ValidateTokenResponse{
// 				Valid:    true,
// 				UserID:   "admin-123",
// 				Email:    "admin@example.com",
// 				Username: "admin",
// 				Roles:    []string{"admin"},
// 			}, nil)

// 		// Mock user list retrieval
// 		suite.userService.On("ListUsers", mock.Anything, mock.AnythingOfType("*user.ListUsersRequest")).Return(
// 			&user.ListUsersResponse{
// 				Users: []*user.UserProfile{},
// 				Total: 0,
// 			}, nil)

// 		req, _ := http.NewRequest("GET", "/api/v1/users?page=1&limit=10", nil)
// 		req.Header.Set("Authorization", "Bearer admin-token")
// 		w := httptest.NewRecorder()
// 		suite.server.router.ServeHTTP(w, req)

// 		assert.Equal(suite.T(), http.StatusOK, w.Code)

// 		var response PaginatedResponse
// 		err := json.Unmarshal(w.Body.Bytes(), &response)
// 		assert.NoError(suite.T(), err)
// 		assert.True(suite.T(), response.Success)
// 		assert.NotNil(suite.T(), response.Pagination)
// 	})
// }

// // TestErrorHandling tests error handling
// func (suite *RestAPITestSuite) TestErrorHandling() {
// 	suite.Run("Service error handling", func() {
// 		// Mock service error
// 		suite.authService.On("Register", mock.Anything, mock.AnythingOfType("*auth.RegisterRequest")).Return(
// 			(*auth.RegisterResponse)(nil),
// 			auth.ErrUserAlreadyExists)

// 		reqBody := map[string]interface{}{
// 			"email":    "existing@example.com",
// 			"password": "password123",
// 		}
// 		body, _ := json.Marshal(reqBody)

// 		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
// 		req.Header.Set("Content-Type", "application/json")
// 		w := httptest.NewRecorder()
// 		suite.server.router.ServeHTTP(w, req)

// 		// Should handle the service error appropriately
// 		assert.NotEqual(suite.T(), http.StatusOK, w.Code)
// 	})
// }

// // Run the test suite
// func TestRestAPITestSuite(t *testing.T) {
// 	suite.Run(t, new(RestAPITestSuite))
// }
