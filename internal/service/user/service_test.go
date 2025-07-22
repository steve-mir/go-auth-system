package user

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*UserData, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

func (m *MockUserRepository) GetUserByUsername(ctx context.Context, username string) (*UserData, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

func (m *MockUserRepository) UpdateUser(ctx context.Context, userID string, data *UpdateUserData) (*UserData, error) {
	args := m.Called(ctx, userID, data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserData), args.Error(1)
}

func (m *MockUserRepository) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) ListUsers(ctx context.Context, limit, offset int32) ([]*UserData, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*UserData), args.Error(1)
}

func (m *MockUserRepository) CountUsers(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserRepository) GetUsersByRole(ctx context.Context, roleName string) ([]*UserData, error) {
	args := m.Called(ctx, roleName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*UserData), args.Error(1)
}

func (m *MockUserRepository) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]string), args.Error(1)
}

type MockSessionRepository struct {
	mock.Mock
}

func (m *MockSessionRepository) DeleteUserSessions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

type MockAuditRepository struct {
	mock.Mock
}

func (m *MockAuditRepository) LogUserAction(ctx context.Context, action *AuditLogData) error {
	args := m.Called(ctx, action)
	return args.Error(0)
}

type MockHashService struct {
	mock.Mock
}

func (m *MockHashService) HashPassword(ctx context.Context, password string) (string, error) {
	args := m.Called(ctx, password)
	return args.String(0), args.Error(1)
}

func (m *MockHashService) VerifyPassword(ctx context.Context, password, hash string) error {
	args := m.Called(ctx, password, hash)
	return args.Error(0)
}

func (m *MockHashService) NeedsRehash(ctx context.Context, hash string) bool {
	args := m.Called(ctx, hash)
	return args.Bool(0)
}

type MockEncryptor struct {
	mock.Mock
}

func (m *MockEncryptor) Encrypt(data []byte) ([]byte, error) {
	args := m.Called(data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockEncryptor) Decrypt(encryptedData []byte) ([]byte, error) {
	args := m.Called(encryptedData)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// Test setup helper
func setupUserService() (*Service, *MockUserRepository, *MockSessionRepository, *MockAuditRepository, *MockHashService, *MockEncryptor) {
	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	auditRepo := &MockAuditRepository{}
	hashService := &MockHashService{}
	encryptor := &MockEncryptor{}

	deps := &Dependencies{
		UserRepo:    userRepo,
		SessionRepo: sessionRepo,
		AuditRepo:   auditRepo,
		HashService: hashService,
		Encryptor:   encryptor,
	}

	service := NewService(deps)
	return service, userRepo, sessionRepo, auditRepo, hashService, encryptor
}

// Helper function to create test user data
func createTestUserData() *UserData {
	userID := uuid.New().String()
	now := time.Now().Unix()

	return &UserData{
		ID:                 userID,
		Email:              "test@example.com",
		Username:           "testuser",
		PasswordHash:       "hashed_password",
		HashAlgorithm:      "argon2",
		FirstNameEncrypted: []byte("encrypted_john"),
		LastNameEncrypted:  []byte("encrypted_doe"),
		PhoneEncrypted:     []byte("encrypted_phone"),
		EmailVerified:      true,
		PhoneVerified:      false,
		AccountLocked:      false,
		FailedAttempts:     0,
		LastLoginAt:        &now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

func TestService_GetProfile(t *testing.T) {
	service, userRepo, _, _, _, encryptor := setupUserService()
	ctx := context.Background()

	t.Run("successful profile retrieval", func(t *testing.T) {
		userData := createTestUserData()
		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		userRepo.On("GetUserRoles", ctx, userData.ID).Return([]string{"user"}, nil)

		// Mock decryption
		encryptor.On("Decrypt", userData.FirstNameEncrypted).Return([]byte("John"), nil)
		encryptor.On("Decrypt", userData.LastNameEncrypted).Return([]byte("Doe"), nil)
		encryptor.On("Decrypt", userData.PhoneEncrypted).Return([]byte("+1234567890"), nil)

		profile, err := service.GetProfile(ctx, userData.ID)

		require.NoError(t, err)
		assert.Equal(t, userData.Email, profile.Email)
		assert.Equal(t, userData.Username, profile.Username)
		assert.Equal(t, "John", profile.FirstName)
		assert.Equal(t, "Doe", profile.LastName)
		assert.Equal(t, "+1234567890", profile.Phone)
		assert.Equal(t, []string{"user"}, profile.Roles)
		assert.True(t, profile.Verified.Email)
		assert.False(t, profile.Verified.Phone)
		assert.False(t, profile.Status.Locked)

		userRepo.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		_, err := service.GetProfile(ctx, "invalid-uuid")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be a valid UUID")
	})

	t.Run("user not found", func(t *testing.T) {
		userID := uuid.New().String()
		userRepo.On("GetUserByID", ctx, userID).Return(nil, sql.ErrNoRows)

		_, err := service.GetProfile(ctx, userID)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")

		userRepo.AssertExpectations(t)
	})

	t.Run("decryption error", func(t *testing.T) {
		userData := createTestUserData()
		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		encryptor.On("Decrypt", userData.FirstNameEncrypted).Return(nil, assert.AnError)

		_, err := service.GetProfile(ctx, userData.ID)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to decrypt")

		userRepo.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})
}

func TestService_UpdateProfile(t *testing.T) {
	service, userRepo, _, auditRepo, _, encryptor := setupUserService()
	ctx := context.Background()

	t.Run("successful profile update", func(t *testing.T) {
		userData := createTestUserData()
		newEmail := "newemail@example.com"
		newFirstName := "Jane"

		req := &UpdateProfileRequest{
			Email:     &newEmail,
			FirstName: &newFirstName,
		}

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil).Twice()
		encryptor.On("Encrypt", []byte(newFirstName)).Return([]byte("encrypted_jane"), nil)

		updatedUserData := *userData
		updatedUserData.Email = newEmail
		updatedUserData.FirstNameEncrypted = []byte("encrypted_jane")

		userRepo.On("UpdateUser", ctx, userData.ID, mock.AnythingOfType("*user.UpdateUserData")).Return(&updatedUserData, nil)
		userRepo.On("GetUserRoles", ctx, userData.ID).Return([]string{"user"}, nil)

		// Mock decryption for response
		encryptor.On("Decrypt", []byte("encrypted_jane")).Return([]byte("Jane"), nil)
		encryptor.On("Decrypt", userData.LastNameEncrypted).Return([]byte("Doe"), nil)
		encryptor.On("Decrypt", userData.PhoneEncrypted).Return([]byte("+1234567890"), nil)

		auditRepo.On("LogUserAction", mock.Anything, mock.AnythingOfType("*user.AuditLogData")).Return(nil)

		profile, err := service.UpdateProfile(ctx, userData.ID, req)

		require.NoError(t, err)
		assert.Equal(t, newEmail, profile.Email)
		assert.Equal(t, "Jane", profile.FirstName)

		userRepo.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})

	t.Run("user locked", func(t *testing.T) {
		userData := createTestUserData()
		userData.AccountLocked = true

		req := &UpdateProfileRequest{
			FirstName: stringPtr("Jane"),
		}

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)

		_, err := service.UpdateProfile(ctx, userData.ID, req)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "locked")

		userRepo.AssertExpectations(t)
	})

	t.Run("encryption error", func(t *testing.T) {
		userData := createTestUserData()
		newFirstName := "Jane"

		req := &UpdateProfileRequest{
			FirstName: &newFirstName,
		}

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		encryptor.On("Encrypt", []byte(newFirstName)).Return(nil, assert.AnError)

		_, err := service.UpdateProfile(ctx, userData.ID, req)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to encrypt")

		userRepo.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})
}

func TestService_DeleteUser(t *testing.T) {
	service, userRepo, sessionRepo, auditRepo, _, _ := setupUserService()
	ctx := context.Background()

	t.Run("successful user deletion", func(t *testing.T) {
		userData := createTestUserData()

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		sessionRepo.On("DeleteUserSessions", ctx, userData.ID).Return(nil)
		userRepo.On("DeleteUser", ctx, userData.ID).Return(nil)
		auditRepo.On("LogUserAction", mock.Anything, mock.AnythingOfType("*user.AuditLogData")).Return(nil)

		err := service.DeleteUser(ctx, userData.ID)

		require.NoError(t, err)

		userRepo.AssertExpectations(t)
		sessionRepo.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		userID := uuid.New().String()
		userRepo.On("GetUserByID", ctx, userID).Return(nil, sql.ErrNoRows)

		err := service.DeleteUser(ctx, userID)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")

		userRepo.AssertExpectations(t)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		err := service.DeleteUser(ctx, "invalid-uuid")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be a valid UUID")
	})
}

func TestService_ListUsers(t *testing.T) {
	service, userRepo, _, _, _, encryptor := setupUserService()
	ctx := context.Background()

	t.Run("successful user listing", func(t *testing.T) {
		userData1 := createTestUserData()
		userData2 := createTestUserData()
		userData2.ID = uuid.New().String()
		userData2.Email = "user2@example.com"

		req := &ListUsersRequest{
			Page:     1,
			PageSize: 20,
		}

		userRepo.On("ListUsers", ctx, int32(20), int32(0)).Return([]*UserData{userData1, userData2}, nil)
		userRepo.On("CountUsers", ctx).Return(int64(2), nil)
		userRepo.On("GetUserRoles", ctx, userData1.ID).Return([]string{"user"}, nil)
		userRepo.On("GetUserRoles", ctx, userData2.ID).Return([]string{"admin"}, nil)

		// Mock decryption for both users
		encryptor.On("Decrypt", userData1.FirstNameEncrypted).Return([]byte("John"), nil)
		encryptor.On("Decrypt", userData1.LastNameEncrypted).Return([]byte("Doe"), nil)
		encryptor.On("Decrypt", userData1.PhoneEncrypted).Return([]byte("+1234567890"), nil)
		encryptor.On("Decrypt", userData2.FirstNameEncrypted).Return([]byte("John"), nil)
		encryptor.On("Decrypt", userData2.LastNameEncrypted).Return([]byte("Doe"), nil)
		encryptor.On("Decrypt", userData2.PhoneEncrypted).Return([]byte("+1234567890"), nil)

		response, err := service.ListUsers(ctx, req)

		require.NoError(t, err)
		assert.Len(t, response.Users, 2)
		assert.Equal(t, int64(2), response.Total)
		assert.Equal(t, int32(1), response.Page)
		assert.Equal(t, int32(20), response.PageSize)
		assert.Equal(t, int32(1), response.TotalPages)

		userRepo.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})

	t.Run("list users by role", func(t *testing.T) {
		userData := createTestUserData()

		req := &ListUsersRequest{
			Page:     1,
			PageSize: 20,
			Role:     "admin",
		}

		userRepo.On("GetUsersByRole", ctx, "admin").Return([]*UserData{userData}, nil)
		userRepo.On("CountUsers", ctx).Return(int64(1), nil)
		userRepo.On("GetUserRoles", ctx, userData.ID).Return([]string{"admin"}, nil)

		// Mock decryption
		encryptor.On("Decrypt", userData.FirstNameEncrypted).Return([]byte("John"), nil)
		encryptor.On("Decrypt", userData.LastNameEncrypted).Return([]byte("Doe"), nil)
		encryptor.On("Decrypt", userData.PhoneEncrypted).Return([]byte("+1234567890"), nil)

		response, err := service.ListUsers(ctx, req)

		require.NoError(t, err)
		assert.Len(t, response.Users, 1)
		assert.Equal(t, []string{"admin"}, response.Users[0].Roles)

		userRepo.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})

	t.Run("default pagination", func(t *testing.T) {
		req := &ListUsersRequest{} // Empty request should use defaults

		userRepo.On("ListUsers", ctx, int32(20), int32(0)).Return([]*UserData{}, nil)
		userRepo.On("CountUsers", ctx).Return(int64(0), nil)

		response, err := service.ListUsers(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, int32(1), response.Page)
		assert.Equal(t, int32(20), response.PageSize)

		userRepo.AssertExpectations(t)
	})
}

func TestService_ChangePassword(t *testing.T) {
	service, userRepo, _, auditRepo, hashService, _ := setupUserService()
	ctx := context.Background()

	t.Run("successful password change", func(t *testing.T) {
		userData := createTestUserData()

		req := &ChangePasswordRequest{
			CurrentPassword: "oldpassword",
			NewPassword:     "newpassword123",
		}

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		hashService.On("VerifyPassword", ctx, "oldpassword", userData.PasswordHash).Return(nil)
		hashService.On("HashPassword", ctx, "newpassword123").Return("new_hashed_password", nil)
		userRepo.On("UpdateUser", ctx, userData.ID, mock.AnythingOfType("*user.UpdateUserData")).Return(userData, nil)
		auditRepo.On("LogUserAction", mock.Anything, mock.AnythingOfType("*user.AuditLogData")).Return(nil)

		err := service.ChangePassword(ctx, userData.ID, req)

		require.NoError(t, err)

		userRepo.AssertExpectations(t)
		hashService.AssertExpectations(t)
	})

	t.Run("invalid current password", func(t *testing.T) {
		userData := createTestUserData()

		req := &ChangePasswordRequest{
			CurrentPassword: "wrongpassword",
			NewPassword:     "newpassword123",
		}

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		hashService.On("VerifyPassword", ctx, "wrongpassword", userData.PasswordHash).Return(assert.AnError)

		err := service.ChangePassword(ctx, userData.ID, req)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "incorrect")

		userRepo.AssertExpectations(t)
		hashService.AssertExpectations(t)
	})

	t.Run("user locked", func(t *testing.T) {
		userData := createTestUserData()
		userData.AccountLocked = true

		req := &ChangePasswordRequest{
			CurrentPassword: "oldpassword",
			NewPassword:     "newpassword123",
		}

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)

		err := service.ChangePassword(ctx, userData.ID, req)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "locked")

		userRepo.AssertExpectations(t)
	})
}

func TestService_GetUserRoles(t *testing.T) {
	service, userRepo, _, _, _, _ := setupUserService()
	ctx := context.Background()

	t.Run("successful role retrieval", func(t *testing.T) {
		userData := createTestUserData()
		expectedRoles := []string{"user", "admin"}

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		userRepo.On("GetUserRoles", ctx, userData.ID).Return(expectedRoles, nil)

		roles, err := service.GetUserRoles(ctx, userData.ID)

		require.NoError(t, err)
		assert.Equal(t, expectedRoles, roles)

		userRepo.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		userID := uuid.New().String()
		userRepo.On("GetUserByID", ctx, userID).Return(nil, sql.ErrNoRows)

		_, err := service.GetUserRoles(ctx, userID)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")

		userRepo.AssertExpectations(t)
	})
}

// Helper function
// func stringPtr(s string) *string {
// 	return &s
// }
