package rest

// import (
// 	"bytes"
// 	"context"
// 	"encoding/json"
// 	"net/http"
// 	"net/http/httptest"
// 	"testing"

// 	"github.com/gin-gonic/gin"
// 	"github.com/steve-mir/go-auth-system/internal/service/mfa"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// )

// // MockMFAService is a mock implementation of the MFA service
// type MockMFAService struct {
// 	mock.Mock
// }

// func (m *MockMFAService) SetupTOTP(ctx context.Context, req *mfa.SetupTOTPRequest) (*mfa.SetupTOTPResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.SetupTOTPResponse), args.Error(1)
// }

// func (m *MockMFAService) VerifyTOTP(ctx context.Context, req *mfa.VerifyTOTPRequest) (*mfa.VerifyTOTPResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.VerifyTOTPResponse), args.Error(1)
// }

// func (m *MockMFAService) SetupSMS(ctx context.Context, req *mfa.SetupSMSRequest) (*mfa.SetupSMSResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.SetupSMSResponse), args.Error(1)
// }

// func (m *MockMFAService) SendSMSCode(ctx context.Context, req *mfa.SendSMSCodeRequest) (*mfa.SendSMSCodeResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.SendSMSCodeResponse), args.Error(1)
// }

// func (m *MockMFAService) VerifySMS(ctx context.Context, req *mfa.VerifySMSRequest) (*mfa.VerifySMSResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.VerifySMSResponse), args.Error(1)
// }

// func (m *MockMFAService) SetupEmail(ctx context.Context, req *mfa.SetupEmailRequest) (*mfa.SetupEmailResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.SetupEmailResponse), args.Error(1)
// }

// func (m *MockMFAService) SendEmailCode(ctx context.Context, req *mfa.SendEmailCodeRequest) (*mfa.SendEmailCodeResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.SendEmailCodeResponse), args.Error(1)
// }

// func (m *MockMFAService) VerifyEmail(ctx context.Context, req *mfa.VerifyEmailRequest) (*mfa.VerifyEmailResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.VerifyEmailResponse), args.Error(1)
// }

// func (m *MockMFAService) SetupWebAuthn(ctx context.Context, req *mfa.SetupWebAuthnRequest) (*mfa.SetupWebAuthnResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.SetupWebAuthnResponse), args.Error(1)
// }

// func (m *MockMFAService) FinishWebAuthnSetup(ctx context.Context, req *mfa.FinishWebAuthnSetupRequest) (*mfa.FinishWebAuthnSetupResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.FinishWebAuthnSetupResponse), args.Error(1)
// }

// func (m *MockMFAService) BeginWebAuthnLogin(ctx context.Context, req *mfa.BeginWebAuthnLoginRequest) (*mfa.BeginWebAuthnLoginResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.BeginWebAuthnLoginResponse), args.Error(1)
// }

// func (m *MockMFAService) FinishWebAuthnLogin(ctx context.Context, req *mfa.FinishWebAuthnLoginRequest) (*mfa.FinishWebAuthnLoginResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.FinishWebAuthnLoginResponse), args.Error(1)
// }

// func (m *MockMFAService) GenerateBackupCodes(ctx context.Context, req *mfa.GenerateBackupCodesRequest) (*mfa.GenerateBackupCodesResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.GenerateBackupCodesResponse), args.Error(1)
// }

// func (m *MockMFAService) VerifyBackupCode(ctx context.Context, req *mfa.VerifyBackupCodeRequest) (*mfa.VerifyBackupCodeResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.VerifyBackupCodeResponse), args.Error(1)
// }

// func (m *MockMFAService) GetUserMFAMethods(ctx context.Context, userID string) (*mfa.GetUserMFAMethodsResponse, error) {
// 	args := m.Called(ctx, userID)
// 	return args.Get(0).(*mfa.GetUserMFAMethodsResponse), args.Error(1)
// }

// func (m *MockMFAService) DisableMFA(ctx context.Context, req *mfa.DisableMFARequest) error {
// 	args := m.Called(ctx, req)
// 	return args.Error(0)
// }

// func (m *MockMFAService) ValidateMFAForLogin(ctx context.Context, req *mfa.ValidateMFAForLoginRequest) (*mfa.ValidateMFAForLoginResponse, error) {
// 	args := m.Called(ctx, req)
// 	return args.Get(0).(*mfa.ValidateMFAForLoginResponse), args.Error(1)
// }

// // Helper function to create a test server with mock MFA service
// func setupTestServer(mockMFAService *MockMFAService) *gin.Engine {
// 	gin.SetMode(gin.TestMode)
// 	router := gin.New()

// 	// Create a mock server with the MFA service
// 	server := &Server{
// 		mfaService: mockMFAService,
// 	}

// 	// Add helper methods for testing
// 	server.bindAndValidate = func(c *gin.Context, req interface{}) bool {
// 		if err := c.ShouldBindJSON(req); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
// 			return false
// 		}
// 		return true
// 	}

// 	server.handleServiceError = func(c *gin.Context, err error) {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 	}

// 	server.successResponse = func(c *gin.Context, statusCode int, data interface{}) {
// 		c.JSON(statusCode, data)
// 	}

// 	// Setup MFA routes
// 	v1 := router.Group("/api/v1")
// 	server.setupMFARoutes(v1)

// 	return router
// }

// func TestSetupTOTPHandler(t *testing.T) {
// 	mockService := new(MockMFAService)
// 	router := setupTestServer(mockService)

// 	// Mock the service response
// 	expectedResponse := &mfa.SetupTOTPResponse{
// 		ConfigID:    "config-123",
// 		Secret:      "JBSWY3DPEHPK3PXP",
// 		QRCodeURL:   "otpauth://totp/test",
// 		BackupCodes: []string{"12345678", "87654321"},
// 		SetupToken:  "setup-token-123",
// 		Message:     "TOTP setup initiated",
// 	}

// 	mockService.On("SetupTOTP", mock.Anything, mock.AnythingOfType("*mfa.SetupTOTPRequest")).Return(expectedResponse, nil)

// 	// Create request
// 	requestBody := mfa.SetupTOTPRequest{
// 		UserID:      "user-123",
// 		AccountName: "test@example.com",
// 		Issuer:      "TestApp",
// 	}

// 	jsonBody, _ := json.Marshal(requestBody)
// 	req, _ := http.NewRequest("POST", "/api/v1/mfa/totp/setup", bytes.NewBuffer(jsonBody))
// 	req.Header.Set("Content-Type", "application/json")

// 	// Perform request
// 	w := httptest.NewRecorder()
// 	router.ServeHTTP(w, req)

// 	// Assert response
// 	assert.Equal(t, http.StatusOK, w.Code)

// 	var response mfa.SetupTOTPResponse
// 	err := json.Unmarshal(w.Body.Bytes(), &response)
// 	assert.NoError(t, err)
// 	assert.Equal(t, expectedResponse.ConfigID, response.ConfigID)
// 	assert.Equal(t, expectedResponse.Secret, response.Secret)

// 	mockService.AssertExpectations(t)
// }

// func TestVerifyTOTPHandler(t *testing.T) {
// 	mockService := new(MockMFAService)
// 	router := setupTestServer(mockService)

// 	// Test successful verification
// 	t.Run("Valid TOTP Code", func(t *testing.T) {
// 		expectedResponse := &mfa.VerifyTOTPResponse{
// 			Valid:         true,
// 			ConfigID:      "config-123",
// 			Message:       "TOTP verified successfully",
// 			SetupComplete: true,
// 		}

// 		mockService.On("VerifyTOTP", mock.Anything, mock.AnythingOfType("*mfa.VerifyTOTPRequest")).Return(expectedResponse, nil)

// 		requestBody := mfa.VerifyTOTPRequest{
// 			UserID:   "user-123",
// 			ConfigID: "config-123",
// 			Code:     "123456",
// 			ForLogin: true,
// 		}

// 		jsonBody, _ := json.Marshal(requestBody)
// 		req, _ := http.NewRequest("POST", "/api/v1/mfa/totp/verify", bytes.NewBuffer(jsonBody))
// 		req.Header.Set("Content-Type", "application/json")

// 		w := httptest.NewRecorder()
// 		router.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusOK, w.Code)

// 		var response mfa.VerifyTOTPResponse
// 		err := json.Unmarshal(w.Body.Bytes(), &response)
// 		assert.NoError(t, err)
// 		assert.True(t, response.Valid)
// 		assert.Equal(t, expectedResponse.ConfigID, response.ConfigID)
// 	})

// 	// Test invalid TOTP code
// 	t.Run("Invalid TOTP Code", func(t *testing.T) {
// 		expectedResponse := &mfa.VerifyTOTPResponse{
// 			Valid:    false,
// 			ConfigID: "config-123",
// 			Message:  "Invalid TOTP code",
// 		}

// 		mockService.On("VerifyTOTP", mock.Anything, mock.AnythingOfType("*mfa.VerifyTOTPRequest")).Return(expectedResponse, nil)

// 		requestBody := mfa.VerifyTOTPRequest{
// 			UserID:   "user-123",
// 			ConfigID: "config-123",
// 			Code:     "000000",
// 			ForLogin: true,
// 		}

// 		jsonBody, _ := json.Marshal(requestBody)
// 		req, _ := http.NewRequest("POST", "/api/v1/mfa/totp/verify", bytes.NewBuffer(jsonBody))
// 		req.Header.Set("Content-Type", "application/json")

// 		w := httptest.NewRecorder()
// 		router.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 	})

// 	mockService.AssertExpectations(t)
// }

// func TestGetUserMFAMethodsHandler(t *testing.T) {
// 	mockService := new(MockMFAService)
// 	router := setupTestServer(mockService)

// 	expectedResponse := &mfa.GetUserMFAMethodsResponse{
// 		Methods: []mfa.MFAMethodInfo{
// 			{
// 				Method:      "totp",
// 				Enabled:     true,
// 				DisplayName: "Authenticator App",
// 			},
// 			{
// 				Method:      "sms",
// 				Enabled:     true,
// 				DisplayName: "SMS to +1***-***-7890",
// 			},
// 		},
// 	}

// 	mockService.On("GetUserMFAMethods", mock.Anything, "user-123").Return(expectedResponse, nil)

// 	req, _ := http.NewRequest("GET", "/api/v1/mfa/methods/user-123", nil)
// 	w := httptest.NewRecorder()
// 	router.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusOK, w.Code)

// 	var response mfa.GetUserMFAMethodsResponse
// 	err := json.Unmarshal(w.Body.Bytes(), &response)
// 	assert.NoError(t, err)
// 	assert.Len(t, response.Methods, 2)
// 	assert.Equal(t, "totp", response.Methods[0].Method)
// 	assert.Equal(t, "sms", response.Methods[1].Method)

// 	mockService.AssertExpectations(t)
// }

// func TestDisableMFAHandler(t *testing.T) {
// 	mockService := new(MockMFAService)
// 	router := setupTestServer(mockService)

// 	mockService.On("DisableMFA", mock.Anything, mock.AnythingOfType("*mfa.DisableMFARequest")).Return(nil)

// 	requestBody := mfa.DisableMFARequest{
// 		UserID:   "user-123",
// 		ConfigID: "config-123",
// 		Method:   "totp",
// 	}

// 	jsonBody, _ := json.Marshal(requestBody)
// 	req, _ := http.NewRequest("POST", "/api/v1/mfa/disable", bytes.NewBuffer(jsonBody))
// 	req.Header.Set("Content-Type", "application/json")

// 	w := httptest.NewRecorder()
// 	router.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusOK, w.Code)

// 	var response map[string]string
// 	err := json.Unmarshal(w.Body.Bytes(), &response)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "MFA method disabled successfully", response["message"])

// 	mockService.AssertExpectations(t)
// }

// func TestValidateMFAForLoginHandler(t *testing.T) {
// 	mockService := new(MockMFAService)
// 	router := setupTestServer(mockService)

// 	expectedResponse := &mfa.ValidateMFAForLoginResponse{
// 		MFARequired: true,
// 		Methods:     []string{"totp", "sms"},
// 		Configs: []mfa.MFAConfigInfo{
// 			{
// 				ID:          "config-123",
// 				Method:      "totp",
// 				DisplayName: "Authenticator App",
// 			},
// 		},
// 		Challenge: "challenge-token-123",
// 	}

// 	mockService.On("ValidateMFAForLogin", mock.Anything, mock.AnythingOfType("*mfa.ValidateMFAForLoginRequest")).Return(expectedResponse, nil)

// 	requestBody := mfa.ValidateMFAForLoginRequest{
// 		UserID: "user-123",
// 	}

// 	jsonBody, _ := json.Marshal(requestBody)
// 	req, _ := http.NewRequest("POST", "/api/v1/mfa/validate-login", bytes.NewBuffer(jsonBody))
// 	req.Header.Set("Content-Type", "application/json")

// 	w := httptest.NewRecorder()
// 	router.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusOK, w.Code)

// 	var response mfa.ValidateMFAForLoginResponse
// 	err := json.Unmarshal(w.Body.Bytes(), &response)
// 	assert.NoError(t, err)
// 	assert.True(t, response.MFARequired)
// 	assert.Len(t, response.Methods, 2)
// 	assert.Equal(t, "challenge-token-123", response.Challenge)

// 	mockService.AssertExpectations(t)
// }

// func TestInvalidJSONRequest(t *testing.T) {
// 	mockService := new(MockMFAService)
// 	router := setupTestServer(mockService)

// 	// Send invalid JSON
// 	req, _ := http.NewRequest("POST", "/api/v1/mfa/totp/setup", bytes.NewBuffer([]byte("invalid json")))
// 	req.Header.Set("Content-Type", "application/json")

// 	w := httptest.NewRecorder()
// 	router.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusBadRequest, w.Code)

// 	var response map[string]string
// 	err := json.Unmarshal(w.Body.Bytes(), &response)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "Invalid JSON format", response["error"])
// }
