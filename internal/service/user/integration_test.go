package user

import (
	"context"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestUserServiceIntegration tests the user service with mock dependencies
func TestUserServiceIntegration(t *testing.T) {
	// Skip integration tests in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	service, userRepo, sessionRepo, auditRepo, hashService, encryptor := setupUserService()
	log.Println("HashService", hashService) // TODO: Remove line.
	ctx := context.Background()

	t.Run("complete user profile workflow", func(t *testing.T) {
		userData := createTestUserData()

		// Test GetProfile
		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		userRepo.On("GetUserRoles", ctx, userData.ID).Return([]string{"user"}, nil)

		// Mock decryption
		encryptor.On("Decrypt", userData.FirstNameEncrypted).Return([]byte("John"), nil)
		encryptor.On("Decrypt", userData.LastNameEncrypted).Return([]byte("Doe"), nil)
		encryptor.On("Decrypt", userData.PhoneEncrypted).Return([]byte("+1234567890"), nil)

		profile, err := service.GetProfile(ctx, userData.ID)
		require.NoError(t, err)
		assert.Equal(t, userData.Email, profile.Email)
		assert.Equal(t, "John", profile.FirstName)

		// Test UpdateProfile
		newEmail := "updated@example.com"
		updateReq := &UpdateProfileRequest{
			Email: &newEmail,
		}

		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		userRepo.On("GetUserByEmail", ctx, newEmail).Return(nil, assert.AnError) // Email not in use

		updatedUserData := *userData
		updatedUserData.Email = newEmail

		userRepo.On("UpdateUser", ctx, userData.ID, mock.AnythingOfType("*user.UpdateUserData")).Return(&updatedUserData, nil)
		userRepo.On("GetUserRoles", ctx, userData.ID).Return([]string{"user"}, nil)

		// Mock decryption for response
		encryptor.On("Decrypt", userData.FirstNameEncrypted).Return([]byte("John"), nil)
		encryptor.On("Decrypt", userData.LastNameEncrypted).Return([]byte("Doe"), nil)
		encryptor.On("Decrypt", userData.PhoneEncrypted).Return([]byte("+1234567890"), nil)

		auditRepo.On("LogUserAction", mock.Anything, mock.AnythingOfType("*user.AuditLogData")).Return(nil)

		updatedProfile, err := service.UpdateProfile(ctx, userData.ID, updateReq)
		require.NoError(t, err)
		assert.Equal(t, newEmail, updatedProfile.Email)

		// Test DeleteUser
		userRepo.On("GetUserByID", ctx, userData.ID).Return(userData, nil)
		sessionRepo.On("DeleteUserSessions", ctx, userData.ID).Return(nil)
		userRepo.On("DeleteUser", ctx, userData.ID).Return(nil)
		auditRepo.On("LogUserAction", mock.Anything, mock.AnythingOfType("*user.AuditLogData")).Return(nil)

		err = service.DeleteUser(ctx, userData.ID)
		require.NoError(t, err)

		// Verify all expectations
		userRepo.AssertExpectations(t)
		sessionRepo.AssertExpectations(t)
		auditRepo.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})

	t.Run("user listing with pagination", func(t *testing.T) {
		userData1 := createTestUserData()
		userData2 := createTestUserData()
		userData2.ID = "different-id"
		userData2.Email = "user2@example.com"

		req := &ListUsersRequest{
			Page:     1,
			PageSize: 10,
		}

		userRepo.On("ListUsers", ctx, int32(10), int32(0)).Return([]*UserData{userData1, userData2}, nil)
		userRepo.On("CountUsers", ctx).Return(int64(2), nil)
		userRepo.On("GetUserRoles", ctx, userData1.ID).Return([]string{"user"}, nil)
		userRepo.On("GetUserRoles", ctx, userData2.ID).Return([]string{"admin"}, nil)

		// Mock decryption for both users
		encryptor.On("Decrypt", userData1.FirstNameEncrypted).Return([]byte("John"), nil)
		encryptor.On("Decrypt", userData1.LastNameEncrypted).Return([]byte("Doe"), nil)
		encryptor.On("Decrypt", userData1.PhoneEncrypted).Return([]byte("+1234567890"), nil)
		encryptor.On("Decrypt", userData2.FirstNameEncrypted).Return([]byte("Jane"), nil)
		encryptor.On("Decrypt", userData2.LastNameEncrypted).Return([]byte("Smith"), nil)
		encryptor.On("Decrypt", userData2.PhoneEncrypted).Return([]byte("+0987654321"), nil)

		response, err := service.ListUsers(ctx, req)
		require.NoError(t, err)
		assert.Len(t, response.Users, 2)
		assert.Equal(t, int64(2), response.Total)
		assert.Equal(t, int32(1), response.Page)
		assert.Equal(t, int32(10), response.PageSize)

		userRepo.AssertExpectations(t)
		encryptor.AssertExpectations(t)
	})
}
