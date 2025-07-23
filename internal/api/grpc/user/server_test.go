package user

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
	// "github.com/steve-mir/go-auth-system/internal/service/user"
	"github.com/steve-mir/go-auth-system/pb"
)

// MockUserService is a mock implementation of interfaces.UserService
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) GetProfile(ctx context.Context, userID string) (*interfaces.UserProfile, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*interfaces.UserProfile), args.Error(1)
}

func (m *MockUserService) UpdateProfile(ctx context.Context, userID string, req *interfaces.UpdateProfileRequest) (*interfaces.UserProfile, error) {
	args := m.Called(ctx, userID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*interfaces.UserProfile), args.Error(1)
}

func (m *MockUserService) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) ListUsers(ctx context.Context, req *interfaces.ListUsersRequest) (*interfaces.ListUsersResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*interfaces.ListUsersResponse), args.Error(1)
}

func (m *MockUserService) ChangePassword(ctx context.Context, userID string, req *interfaces.ChangePasswordRequest) error {
	args := m.Called(ctx, userID, req)
	return args.Error(0)
}

func (m *MockUserService) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func TestServer_GetProfile(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.GetProfileRequest
		mockSetup      func(*MockUserService)
		expectedError  bool
		expectedCode   codes.Code
		validateResult func(*testing.T, *pb.GetProfileResponse)
	}{
		{
			name: "successful get profile",
			request: &pb.GetProfileRequest{
				UserId: "user-123",
			},
			mockSetup: func(m *MockUserService) {
				userID := uuid.New()
				now := time.Now()
				lastLogin := now.Add(-time.Hour)

				m.On("GetProfile", mock.Anything, "user-123").Return(&interfaces.UserProfile{
					ID:        userID,
					Email:     "test@example.com",
					Username:  "testuser",
					FirstName: "Test",
					LastName:  "User",
					Phone:     "+1234567890",
					Roles:     []string{"user"},
					CreatedAt: now,
					UpdatedAt: now,
					Verified: struct {
						Email bool `json:"email"`
						Phone bool `json:"phone"`
					}{
						Email: true,
						Phone: false,
					},
					Status: struct {
						Locked         bool       `json:"locked"`
						FailedAttempts int32      `json:"failed_attempts"`
						LastLogin      *time.Time `json:"last_login,omitempty"`
					}{
						Locked:         false,
						FailedAttempts: 0,
						LastLogin:      &lastLogin,
					},
				}, nil)
			},
			expectedError: false,
			validateResult: func(t *testing.T, resp *pb.GetProfileResponse) {
				assert.NotNil(t, resp.UserProfile)
				assert.Equal(t, "test@example.com", resp.UserProfile.Email)
				assert.Equal(t, "testuser", resp.UserProfile.Username)
				assert.True(t, resp.UserProfile.EmailVerified)
				assert.False(t, resp.UserProfile.PhoneVerified)
				assert.False(t, resp.UserProfile.AccountLocked)
				assert.NotNil(t, resp.UserProfile.LastLoginAt)
			},
		},
		{
			name: "missing user_id",
			request: &pb.GetProfileRequest{
				UserId: "",
			},
			mockSetup:     func(m *MockUserService) {},
			expectedError: true,
			expectedCode:  codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockUserService{}
			tt.mockSetup(mockService)

			server := NewServer(mockService)
			ctx := context.Background()

			resp, err := server.GetProfile(ctx, tt.request)

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

func TestServer_UpdateProfile(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.UpdateProfileRequest
		mockSetup      func(*MockUserService)
		expectedError  bool
		expectedCode   codes.Code
		validateResult func(*testing.T, *pb.UpdateProfileResponse)
	}{
		{
			name: "successful profile update",
			request: &pb.UpdateProfileRequest{
				UserId:    "user-123",
				FirstName: stringPtr("Updated"),
				LastName:  stringPtr("Name"),
			},
			mockSetup: func(m *MockUserService) {
				userID := uuid.New()
				now := time.Now()

				m.On("UpdateProfile", mock.Anything, "user-123", mock.MatchedBy(func(req *interfaces.UpdateProfileRequest) bool {
					return req.FirstName != nil && *req.FirstName == "Updated" &&
						req.LastName != nil && *req.LastName == "Name"
				})).Return(&interfaces.UserProfile{
					ID:        userID,
					Email:     "test@example.com",
					Username:  "testuser",
					FirstName: "Updated",
					LastName:  "Name",
					Roles:     []string{"user"},
					CreatedAt: now,
					UpdatedAt: now,
					Verified: struct {
						Email bool `json:"email"`
						Phone bool `json:"phone"`
					}{
						Email: true,
						Phone: false,
					},
					Status: struct {
						Locked         bool       `json:"locked"`
						FailedAttempts int32      `json:"failed_attempts"`
						LastLogin      *time.Time `json:"last_login,omitempty"`
					}{
						Locked:         false,
						FailedAttempts: 0,
					},
				}, nil)
			},
			expectedError: false,
			validateResult: func(t *testing.T, resp *pb.UpdateProfileResponse) {
				assert.NotNil(t, resp.UserProfile)
				assert.Equal(t, "Updated", resp.UserProfile.FirstName)
				assert.Equal(t, "Name", resp.UserProfile.LastName)
				assert.Equal(t, "Profile updated successfully", resp.Message)
			},
		},
		{
			name: "missing user_id",
			request: &pb.UpdateProfileRequest{
				UserId: "",
			},
			mockSetup:     func(m *MockUserService) {},
			expectedError: true,
			expectedCode:  codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockUserService{}
			tt.mockSetup(mockService)

			server := NewServer(mockService)
			ctx := context.Background()

			resp, err := server.UpdateProfile(ctx, tt.request)

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

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
