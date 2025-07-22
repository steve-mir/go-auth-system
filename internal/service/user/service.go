package user

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Service implements the UserService interface
type Service struct {
	deps *Dependencies
}

// NewService creates a new user service instance
func NewService(deps *Dependencies) *Service {
	return &Service{
		deps: deps,
	}
}

// GetProfile retrieves user profile information by user ID
func (s *Service) GetProfile(ctx context.Context, userID string) (*UserProfile, error) {
	// Validate user ID
	if _, err := uuid.Parse(userID); err != nil {
		return nil, NewInvalidInputError("user_id", "must be a valid UUID")
	}

	// Get user data from repository
	userData, err := s.deps.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, NewUserNotFoundError(userID)
		}
		return nil, NewDatabaseError("get user", err)
	}

	// Decrypt sensitive data
	profile, err := s.buildUserProfile(userData)
	if err != nil {
		return nil, err
	}

	// Get user roles
	roles, err := s.deps.UserRepo.GetUserRoles(ctx, userID)
	if err != nil {
		// Log error but don't fail the request
		roles = []string{}
	}
	profile.Roles = roles

	return profile, nil
}

// UpdateProfile updates user profile information with data encryption
func (s *Service) UpdateProfile(ctx context.Context, userID string, req *UpdateProfileRequest) (*UserProfile, error) {
	// Validate user ID
	if _, err := uuid.Parse(userID); err != nil {
		return nil, NewInvalidInputError("user_id", "must be a valid UUID")
	}

	// Get current user data
	currentUser, err := s.deps.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, NewUserNotFoundError(userID)
		}
		return nil, NewDatabaseError("get user", err)
	}

	// Check if user is locked
	if currentUser.AccountLocked {
		return nil, NewUserLockedError(userID)
	}

	// Prepare update data
	updateData := &UpdateUserData{}

	// Handle email update
	if req.Email != nil && *req.Email != currentUser.Email {
		// Check if email is already in use
		if existingUser, err := s.deps.UserRepo.GetUserByEmail(ctx, *req.Email); err == nil && existingUser.ID != userID {
			return nil, NewEmailAlreadyInUseError(*req.Email)
		}
		updateData.Email = req.Email
		// Reset email verification when email changes
		emailVerified := false
		updateData.EmailVerified = &emailVerified
	}

	// Handle username update
	if req.Username != nil && *req.Username != currentUser.Username {
		// Check if username is already in use
		if existingUser, err := s.deps.UserRepo.GetUserByUsername(ctx, *req.Username); err == nil && existingUser.ID != userID {
			return nil, NewUsernameAlreadyInUseError(*req.Username)
		}
		updateData.Username = req.Username
	}

	// Handle encrypted fields
	if req.FirstName != nil {
		encrypted, err := s.encryptString(*req.FirstName)
		if err != nil {
			return nil, NewEncryptionError(err)
		}
		updateData.FirstNameEncrypted = encrypted
	}

	if req.LastName != nil {
		encrypted, err := s.encryptString(*req.LastName)
		if err != nil {
			return nil, NewEncryptionError(err)
		}
		updateData.LastNameEncrypted = encrypted
	}

	if req.Phone != nil {
		encrypted, err := s.encryptString(*req.Phone)
		if err != nil {
			return nil, NewEncryptionError(err)
		}
		updateData.PhoneEncrypted = encrypted
		// Reset phone verification when phone changes
		phoneVerified := false
		updateData.PhoneVerified = &phoneVerified
	}

	// Update user in database
	updatedUser, err := s.deps.UserRepo.UpdateUser(ctx, userID, updateData)
	if err != nil {
		return nil, NewDatabaseError("update user", err)
	}

	// Log the update action
	s.logAuditAction(ctx, userID, "profile_updated", "user", userID, "", "", map[string]interface{}{
		"updated_fields": s.getUpdatedFields(req),
	})

	// Build and return updated profile
	profile, err := s.buildUserProfile(updatedUser)
	if err != nil {
		return nil, err
	}

	// Get user roles
	roles, err := s.deps.UserRepo.GetUserRoles(ctx, userID)
	if err != nil {
		roles = []string{}
	}
	profile.Roles = roles

	return profile, nil
}

// DeleteUser deletes a user and performs proper cleanup
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	// Validate user ID
	if _, err := uuid.Parse(userID); err != nil {
		return NewInvalidInputError("user_id", "must be a valid UUID")
	}

	// Check if user exists
	_, err := s.deps.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewUserNotFoundError(userID)
		}
		return NewDatabaseError("get user", err)
	}

	// Delete user sessions first
	if err := s.deps.SessionRepo.DeleteUserSessions(ctx, userID); err != nil {
		return NewDatabaseError("delete user sessions", err)
	}

	// Delete the user
	if err := s.deps.UserRepo.DeleteUser(ctx, userID); err != nil {
		return NewDatabaseError("delete user", err)
	}

	// Log the deletion action
	s.logAuditAction(ctx, userID, "user_deleted", "user", userID, "", "", map[string]interface{}{
		"deleted_at": time.Now().Unix(),
	})

	return nil
}

// ListUsers retrieves users with pagination and filtering
func (s *Service) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	// Set defaults
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 100 {
		req.PageSize = 20
	}

	// Calculate offset
	offset := (req.Page - 1) * req.PageSize

	var users []*UserData
	var err error

	// Get users based on filter
	if req.Role != "" {
		users, err = s.deps.UserRepo.GetUsersByRole(ctx, req.Role)
		if err != nil {
			return nil, NewDatabaseError("get users by role", err)
		}
	} else {
		users, err = s.deps.UserRepo.ListUsers(ctx, req.PageSize, offset)
		if err != nil {
			return nil, NewDatabaseError("list users", err)
		}
	}

	// Get total count
	total, err := s.deps.UserRepo.CountUsers(ctx)
	if err != nil {
		return nil, NewDatabaseError("count users", err)
	}

	// Convert to user profiles
	profiles := make([]*UserProfile, 0, len(users))
	for _, userData := range users {
		profile, err := s.buildUserProfile(userData)
		if err != nil {
			// Log error but continue with other users
			continue
		}

		// Get user roles
		roles, err := s.deps.UserRepo.GetUserRoles(ctx, userData.ID)
		if err != nil {
			roles = []string{}
		}
		profile.Roles = roles

		profiles = append(profiles, profile)
	}

	// Calculate total pages
	totalPages := int32((total + int64(req.PageSize) - 1) / int64(req.PageSize))

	return &ListUsersResponse{
		Users:      profiles,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
	}, nil
}

// ChangePassword allows users to change their password
func (s *Service) ChangePassword(ctx context.Context, userID string, req *ChangePasswordRequest) error {
	// Validate user ID
	if _, err := uuid.Parse(userID); err != nil {
		return NewInvalidInputError("user_id", "must be a valid UUID")
	}

	// Get current user data
	currentUser, err := s.deps.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewUserNotFoundError(userID)
		}
		return NewDatabaseError("get user", err)
	}

	// Check if user is locked
	if currentUser.AccountLocked {
		return NewUserLockedError(userID)
	}

	// Verify current password
	if err := s.deps.HashService.VerifyPassword(ctx, req.CurrentPassword, currentUser.PasswordHash); err != nil {
		return NewInvalidPasswordError()
	}

	// Hash new password
	newPasswordHash, err := s.deps.HashService.HashPassword(ctx, req.NewPassword)
	if err != nil {
		return NewDatabaseError("hash password", err)
	}

	// Update password in database
	updateData := &UpdateUserData{
		PasswordHash:  &newPasswordHash,
		HashAlgorithm: &currentUser.HashAlgorithm,
	}

	_, err = s.deps.UserRepo.UpdateUser(ctx, userID, updateData)
	if err != nil {
		return NewDatabaseError("update password", err)
	}

	// Log the password change action
	s.logAuditAction(ctx, userID, "password_changed", "user", userID, "", "", map[string]interface{}{
		"changed_at": time.Now().Unix(),
	})

	return nil
}

// GetUserRoles retrieves roles assigned to a user
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	// Validate user ID
	if _, err := uuid.Parse(userID); err != nil {
		return nil, NewInvalidInputError("user_id", "must be a valid UUID")
	}

	// Check if user exists
	_, err := s.deps.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, NewUserNotFoundError(userID)
		}
		return nil, NewDatabaseError("get user", err)
	}

	// Get user roles
	roles, err := s.deps.UserRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, NewDatabaseError("get user roles", err)
	}

	return roles, nil
}

// Helper methods

// buildUserProfile converts UserData to UserProfile with decryption
func (s *Service) buildUserProfile(userData *UserData) (*UserProfile, error) {
	profile := &UserProfile{
		ID:        uuid.MustParse(userData.ID),
		Email:     userData.Email,
		Username:  userData.Username,
		CreatedAt: time.Unix(userData.CreatedAt, 0),
		UpdatedAt: time.Unix(userData.UpdatedAt, 0),
	}

	// Set verification status
	profile.Verified.Email = userData.EmailVerified
	profile.Verified.Phone = userData.PhoneVerified

	// Set account status
	profile.Status.Locked = userData.AccountLocked
	profile.Status.FailedAttempts = userData.FailedAttempts
	if userData.LastLoginAt != nil {
		lastLogin := time.Unix(*userData.LastLoginAt, 0)
		profile.Status.LastLogin = &lastLogin
	}

	// Decrypt sensitive fields
	if len(userData.FirstNameEncrypted) > 0 {
		decrypted, err := s.deps.Encryptor.Decrypt(userData.FirstNameEncrypted)
		if err != nil {
			return nil, NewDecryptionError(err)
		}
		profile.FirstName = string(decrypted)
	}

	if len(userData.LastNameEncrypted) > 0 {
		decrypted, err := s.deps.Encryptor.Decrypt(userData.LastNameEncrypted)
		if err != nil {
			return nil, NewDecryptionError(err)
		}
		profile.LastName = string(decrypted)
	}

	if len(userData.PhoneEncrypted) > 0 {
		decrypted, err := s.deps.Encryptor.Decrypt(userData.PhoneEncrypted)
		if err != nil {
			return nil, NewDecryptionError(err)
		}
		profile.Phone = string(decrypted)
	}

	return profile, nil
}

// encryptString encrypts a string value
func (s *Service) encryptString(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return s.deps.Encryptor.Encrypt([]byte(value))
}

// getUpdatedFields returns a list of fields that were updated
func (s *Service) getUpdatedFields(req *UpdateProfileRequest) []string {
	var fields []string
	if req.Email != nil {
		fields = append(fields, "email")
	}
	if req.Username != nil {
		fields = append(fields, "username")
	}
	if req.FirstName != nil {
		fields = append(fields, "first_name")
	}
	if req.LastName != nil {
		fields = append(fields, "last_name")
	}
	if req.Phone != nil {
		fields = append(fields, "phone")
	}
	return fields
}

// logAuditAction logs an audit action if audit repository is available
func (s *Service) logAuditAction(ctx context.Context, userID, action, resourceType, resourceID, ipAddress, userAgent string, metadata map[string]interface{}) {
	if s.deps.AuditRepo == nil {
		return
	}

	auditData := &AuditLogData{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Metadata:     metadata,
	}

	// Log asynchronously to avoid blocking the main operation
	go func() {
		if err := s.deps.AuditRepo.LogUserAction(context.Background(), auditData); err != nil {
			// Log error but don't fail the operation
			fmt.Printf("Failed to log audit action: %v\n", err)
		}
	}()
}
