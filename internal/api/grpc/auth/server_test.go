package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/steve-mir/go-auth-system/internal/service/auth"
	"github.com/steve-mir/go-auth-system/pb"
)

// MockAuthService is a mock implementation of auth.AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.RegisterResponse), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.LoginResponse), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, req *auth.LogoutRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenResponse), args.Error(1)
}

func (m *MockAuthService) ValidateToken(ctx context.Context, req *auth.ValidateTokenRequest) (*auth.ValidateTokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.ValidateTokenResponse), args.Error(1)
}

func (m *MockAuthService) GetUserProfile(ctx context.Context, token string) (*auth.UserProfile, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.UserProfile), args.Error(1)
}

func (m *MockAuthService) GetUserSessions(ctx context.Context, userID string) ([]*auth.SessionInfo, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*auth.SessionInfo), args.Error(1)
}

func (m *MockAuthService) RevokeUserSessions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthService) RevokeSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func TestServer_Register(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.RegisterRequest
		mockSetup      func(*MockAuthService)
		expectedError  bool
		expectedCode   codes.Code
		validateResult func(*testing.T, *pb.RegisterResponse)
	}{
		{
			name: "successful registration",
			request: &pb.RegisterRequest{
				Email:     "test@example.com",
				Username:  "testuser",
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
				Phone:     "+1234567890",
			},
			mockSetup: func(m *MockAuthService) {
				userID := uuid.New()
				m.On("Register", mock.Anything, mock.MatchedBy(func(req *auth.RegisterRequest) bool {
					return req.Email == "test@example.com" &&
						req.Username == "testuser" &&
						req.Password == "password123" &&
						req.FirstName == "Test" &&
						req.LastName == "User" &&
						req.Phone == "+1234567890"
				})).Return(&auth.RegisterResponse{
					UserID:    userID,
					Email:     "test@example.com",
					Username:  "testuser",
					CreatedAt: time.Now(),
					Message:   "User registered successfully",
				}, nil)
			},
			expectedError: false,
			validateResult: func(t *testing.T, resp *pb.RegisterResponse) {
				assert.NotEmpty(t, resp.UserId)
				assert.Equal(t, "test@example.com", resp.Email)
				assert.Equal(t, "testuser", resp.Username)
				assert.NotNil(t, resp.CreatedAt)
				assert.True(t, resp.EmailVerificationRequired)
			},
		},
		{
			name: "missing email",
			request: &pb.RegisterRequest{
				Username: "testuser",
				Password: "password123",
			},
			mockSetup:     func(m *MockAuthService) {},
			expectedError: true,
			expectedCode:  codes.InvalidArgument,
		},
		{
			name: "missing password",
			request: &pb.RegisterRequest{
				Email:    "test@example.com",
				Username: "testuser",
			},
			mockSetup:     func(m *MockAuthService) {},
			expectedError: true,
			expectedCode:  codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockAuthService{}
			tt.mockSetup(mockService)

			server := NewServer(mockService)
			ctx := context.Background()

			resp, err := server.Register(ctx, tt.request)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.expectedCode != codes.OK {
					st, ok := status.FromError(err)
					assert.True(t, ok)
					assert.Equal(t, tt.expectedCode, st.Code())
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				if tt.validateResult != nil {
					tt.validateResult(t, resp)
				}
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestServer_ValidateToken(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.ValidateTokenRequest
		mockSetup      func(*MockAuthService)
		expectedError  bool
		expectedCode   codes.Code
		validateResult func(*testing.T, *pb.ValidateTokenResponse)
	}{
		{
			name: "valid token",
			request: &pb.ValidateTokenRequest{
				Token: "valid-token",
			},
			mockSetup: func(m *MockAuthService) {
				expiresAt := time.Now().Add(time.Hour)
				m.On("ValidateToken", mock.Anything, mock.MatchedBy(func(req *auth.ValidateTokenRequest) bool {
					return req.Token == "valid-token"
				})).Return(&auth.ValidateTokenResponse{
					Valid:     true,
					UserID:    "user-123",
					Email:     "test@example.com",
					Username:  "testuser",
					Roles:     []string{"user", "admin"},
					ExpiresAt: expiresAt,
				}, nil)
			},
			expectedError: false,
			validateResult: func(t *testing.T, resp *pb.ValidateTokenResponse) {
				assert.True(t, resp.Valid)
				assert.Equal(t, "user-123", resp.UserId)
				assert.Equal(t, []string{"user", "admin"}, resp.Roles)
				assert.NotNil(t, resp.ExpiresAt)
				assert.NotNil(t, resp.Claims)
			},
		},
		{
			name: "invalid token",
			request: &pb.ValidateTokenRequest{
				Token: "invalid-token",
			},
			mockSetup: func(m *MockAuthService) {
				m.On("ValidateToken", mock.Anything, mock.MatchedBy(func(req *auth.ValidateTokenRequest) bool {
					return req.Token == "invalid-token"
				})).Return(nil, assert.AnError)
			},
			expectedError: false, // We return a response with Valid: false instead of error
			validateResult: func(t *testing.T, resp *pb.ValidateTokenResponse) {
				assert.False(t, resp.Valid)
			},
		},
		{
			name: "missing token",
			request: &pb.ValidateTokenRequest{
				Token: "",
			},
			mockSetup:     func(m *MockAuthService) {},
			expectedError: true,
			expectedCode:  codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockAuthService{}
			tt.mockSetup(mockService)

			server := NewServer(mockService)
			ctx := context.Background()

			resp, err := server.ValidateToken(ctx, tt.request)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.expectedCode != codes.OK {
					st, ok := status.FromError(err)
					assert.True(t, ok)
					assert.Equal(t, tt.expectedCode, st.Code())
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				if tt.validateResult != nil {
					tt.validateResult(t, resp)
				}
			}

			mockService.AssertExpectations(t)
		})
	}
}
