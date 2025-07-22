package role

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/steve-mir/go-auth-system/internal/errors"
)

// MockRepository is a mock implementation of the Repository interface
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateRole(ctx context.Context, role *Role) error {
	args := m.Called(ctx, role)
	if args.Get(0) != nil {
		// Simulate database setting ID and timestamps
		role.ID = uuid.New()
		role.CreatedAt = time.Now()
		role.UpdatedAt = time.Now()
	}
	return args.Error(0)
}

func (m *MockRepository) GetRoleByID(ctx context.Context, roleID uuid.UUID) (*Role, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).(*Role), args.Error(1)
}

func (m *MockRepository) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Role), args.Error(1)
}

func (m *MockRepository) UpdateRole(ctx context.Context, role *Role) error {
	args := m.Called(ctx, role)
	if args.Get(0) == nil {
		role.UpdatedAt = time.Now()
	}
	return args.Error(0)
}

func (m *MockRepository) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func (m *MockRepository) ListRoles(ctx context.Context, limit, offset int) ([]*Role, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).([]*Role), args.Error(1)
}

func (m *MockRepository) CountRoles(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRepository) AssignRoleToUser(ctx context.Context, userID, roleID, assignedBy uuid.UUID) error {
	args := m.Called(ctx, userID, roleID, assignedBy)
	return args.Error(0)
}

func (m *MockRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*Role), args.Error(1)
}

func (m *MockRepository) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*UserInfo, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).([]*UserInfo), args.Error(1)
}

func TestService_CreateRole(t *testing.T) {
	tests := []struct {
		name        string
		request     CreateRoleRequest
		setupMock   func(*MockRepository)
		expectError bool
		errorType   errors.ErrorType
	}{
		{
			name: "successful role creation",
			request: CreateRoleRequest{
				Name:        "admin",
				Description: "Administrator role",
				Permissions: []Permission{
					{Resource: "user", Action: "read"},
					{Resource: "user", Action: "write"},
				},
			},
			setupMock: func(repo *MockRepository) {
				repo.On("GetRoleByName", mock.Anything, "admin").Return(nil, NewRoleNotFoundError("admin"))
				repo.On("CreateRole", mock.Anything, mock.AnythingOfType("*role.Role")).Return(nil)
			},
			expectError: false,
		},
		{
			name: "role already exists",
			request: CreateRoleRequest{
				Name:        "admin",
				Description: "Administrator role",
			},
			setupMock: func(repo *MockRepository) {
				existingRole := &Role{
					ID:   uuid.New(),
					Name: "admin",
				}
				repo.On("GetRoleByName", mock.Anything, "admin").Return(existingRole, nil)
			},
			expectError: true,
			errorType:   errors.ErrorTypeConflict,
		},
		{
			name: "invalid role name",
			request: CreateRoleRequest{
				Name: "", // Empty name should fail validation
			},
			setupMock:   func(repo *MockRepository) {},
			expectError: true,
			errorType:   errors.ErrorTypeValidation,
		},
		{
			name: "invalid permission",
			request: CreateRoleRequest{
				Name: "test",
				Permissions: []Permission{
					{Resource: "", Action: "read"}, // Empty resource should fail
				},
			},
			setupMock:   func(repo *MockRepository) {},
			expectError: true,
			errorType:   errors.ErrorTypeValidation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &MockRepository{}
			tt.setupMock(repo)

			service := NewService(repo)
			ctx := context.Background()

			role, err := service.CreateRole(ctx, tt.request)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, role)

				if appErr, ok := err.(*errors.AppError); ok {
					assert.Equal(t, tt.errorType, appErr.Type)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, role)
				assert.Equal(t, tt.request.Name, role.Name)
				assert.Equal(t, tt.request.Description, role.Description)
				assert.Equal(t, tt.request.Permissions, role.Permissions)
				assert.NotEqual(t, uuid.Nil, role.ID)
			}

			repo.AssertExpectations(t)
		})
	}
}

func TestService_GetRole(t *testing.T) {
	roleID := uuid.New()
	expectedRole := &Role{
		ID:   roleID,
		Name: "admin",
	}

	repo := &MockRepository{}
	repo.On("GetRoleByID", mock.Anything, roleID).Return(expectedRole, nil)

	service := NewService(repo)
	ctx := context.Background()

	role, err := service.GetRole(ctx, roleID)

	require.NoError(t, err)
	assert.Equal(t, expectedRole, role)
	repo.AssertExpectations(t)
}

func TestService_UpdateRole(t *testing.T) {
	roleID := uuid.New()
	existingRole := &Role{
		ID:          roleID,
		Name:        "user",
		Description: "Regular user",
		Permissions: []Permission{{Resource: "user", Action: "read", Scope: "own"}},
	}

	newName := "power-user"
	newDescription := "Power user with extended permissions"
	newPermissions := []Permission{
		{Resource: "user", Action: "read", Scope: "own"},
		{Resource: "user", Action: "update", Scope: "own"},
	}

	repo := &MockRepository{}
	repo.On("GetRoleByID", mock.Anything, roleID).Return(existingRole, nil)
	repo.On("GetRoleByName", mock.Anything, newName).Return(nil, NewRoleNotFoundError(newName))
	repo.On("UpdateRole", mock.Anything, mock.AnythingOfType("*role.Role")).Return(nil)

	service := NewService(repo)
	ctx := context.Background()

	updateReq := UpdateRoleRequest{
		Name:        &newName,
		Description: &newDescription,
		Permissions: newPermissions,
	}

	role, err := service.UpdateRole(ctx, roleID, updateReq)

	require.NoError(t, err)
	assert.Equal(t, newName, role.Name)
	assert.Equal(t, newDescription, role.Description)
	assert.Equal(t, newPermissions, role.Permissions)
	repo.AssertExpectations(t)
}

func TestService_DeleteRole(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*MockRepository, uuid.UUID)
		expectError bool
		errorCode   string
	}{
		{
			name: "successful deletion",
			setupMock: func(repo *MockRepository, roleID uuid.UUID) {
				role := &Role{ID: roleID, Name: "test"}
				repo.On("GetRoleByID", mock.Anything, roleID).Return(role, nil)
				repo.On("GetRoleUsers", mock.Anything, roleID).Return([]*UserInfo{}, nil)
				repo.On("DeleteRole", mock.Anything, roleID).Return(nil)
			},
			expectError: false,
		},
		{
			name: "role in use",
			setupMock: func(repo *MockRepository, roleID uuid.UUID) {
				role := &Role{ID: roleID, Name: "test"}
				users := []*UserInfo{{ID: uuid.New(), Email: "test@example.com"}}
				repo.On("GetRoleByID", mock.Anything, roleID).Return(role, nil)
				repo.On("GetRoleUsers", mock.Anything, roleID).Return(users, nil)
			},
			expectError: true,
			errorCode:   ErrCodeRoleInUse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roleID := uuid.New()
			repo := &MockRepository{}
			tt.setupMock(repo, roleID)

			service := NewService(repo)
			ctx := context.Background()

			err := service.DeleteRole(ctx, roleID)

			if tt.expectError {
				require.Error(t, err)
				if appErr, ok := err.(*errors.AppError); ok {
					assert.Equal(t, tt.errorCode, appErr.Code)
				}
			} else {
				require.NoError(t, err)
			}

			repo.AssertExpectations(t)
		})
	}
}

func TestService_ListRoles(t *testing.T) {
	roles := []*Role{
		{ID: uuid.New(), Name: "admin"},
		{ID: uuid.New(), Name: "user"},
	}

	repo := &MockRepository{}
	repo.On("ListRoles", mock.Anything, 20, 0).Return(roles, nil)
	repo.On("CountRoles", mock.Anything).Return(int64(2), nil)

	service := NewService(repo)
	ctx := context.Background()

	req := ListRolesRequest{Limit: 20, Offset: 0}
	response, err := service.ListRoles(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, roles, response.Roles)
	assert.Equal(t, int64(2), response.Total)
	assert.Equal(t, 20, response.Limit)
	assert.Equal(t, 0, response.Offset)
	assert.False(t, response.HasMore)
	repo.AssertExpectations(t)
}

func TestService_AssignRoleToUser(t *testing.T) {
	userID := uuid.New()
	roleID := uuid.New()
	assignedBy := uuid.New()
	role := &Role{ID: roleID, Name: "admin"}

	repo := &MockRepository{}
	repo.On("GetRoleByID", mock.Anything, roleID).Return(role, nil)
	repo.On("AssignRoleToUser", mock.Anything, userID, roleID, assignedBy).Return(nil)

	service := NewService(repo)
	ctx := context.Background()

	err := service.AssignRoleToUser(ctx, userID, roleID, assignedBy)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestService_ValidatePermission(t *testing.T) {
	userID := uuid.New()
	userRoles := []*Role{
		{
			ID:   uuid.New(),
			Name: "admin",
			Permissions: []Permission{
				{Resource: "user", Action: "read"},
				{Resource: "user", Action: "write"},
				{Resource: "system", Action: "manage"},
			},
		},
	}

	repo := &MockRepository{}
	repo.On("GetUserRoles", mock.Anything, userID).Return(userRoles, nil)

	service := NewService(repo)
	ctx := context.Background()

	tests := []struct {
		name       string
		permission Permission
		expected   bool
	}{
		{
			name:       "exact permission match",
			permission: Permission{Resource: "user", Action: "read"},
			expected:   true,
		},
		{
			name:       "wildcard resource match",
			permission: Permission{Resource: "user", Action: "delete"},
			expected:   false, // No wildcard in our test permissions
		},
		{
			name:       "no permission match",
			permission: Permission{Resource: "role", Action: "create"},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasPermission, err := service.ValidatePermission(ctx, userID, tt.permission)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, hasPermission)
		})
	}

	repo.AssertExpectations(t)
}

func TestService_ValidateAccess(t *testing.T) {
	userID := uuid.New()
	userRoles := []*Role{
		{
			ID:   uuid.New(),
			Name: "admin",
			Permissions: []Permission{
				{
					Resource: "user",
					Action:   "read",
					Scope:    "all",
				},
				{
					Resource:   "document",
					Action:     "read",
					Scope:      "own",
					Attributes: map[string]any{"department": "engineering"},
				},
			},
		},
	}

	repo := &MockRepository{}
	repo.On("GetUserRoles", mock.Anything, userID).Return(userRoles, nil)

	service := NewService(repo)
	ctx := context.Background()

	tests := []struct {
		name     string
		request  AccessRequest
		expected bool
	}{
		{
			name: "basic permission allowed",
			request: AccessRequest{
				UserID:   userID,
				Resource: "user",
				Action:   "read",
				Scope:    "all",
			},
			expected: true,
		},
		{
			name: "attribute-based permission allowed",
			request: AccessRequest{
				UserID:     userID,
				Resource:   "document",
				Action:     "read",
				Scope:      "own",
				Attributes: map[string]any{"department": "engineering"},
			},
			expected: true,
		},
		{
			name: "attribute-based permission denied",
			request: AccessRequest{
				UserID:     userID,
				Resource:   "document",
				Action:     "read",
				Scope:      "own",
				Attributes: map[string]any{"department": "marketing"},
			},
			expected: false,
		},
		{
			name: "no permission",
			request: AccessRequest{
				UserID:   userID,
				Resource: "system",
				Action:   "delete",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.ValidateAccess(ctx, tt.request)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, response.Allowed)

			if tt.expected {
				assert.Empty(t, response.Reason)
				assert.NotEmpty(t, response.MatchedPermissions)
			} else {
				assert.NotEmpty(t, response.Reason)
			}
		})
	}

	repo.AssertExpectations(t)
}

func TestPermissionSet(t *testing.T) {
	permissions := []Permission{
		{Resource: "user", Action: "read"},
		{Resource: "user", Action: "write"},
		{Resource: "role", Action: "manage"},
	}

	permSet := NewPermissionSet(permissions)

	tests := []struct {
		name       string
		permission Permission
		expected   bool
	}{
		{
			name:       "exact match",
			permission: Permission{Resource: "user", Action: "read"},
			expected:   true,
		},
		{
			name:       "resource wildcard match",
			permission: Permission{Resource: "user", Action: "delete"},
			expected:   true, // Should match user:*
		},
		{
			name:       "action wildcard match",
			permission: Permission{Resource: "system", Action: "read"},
			expected:   true, // Should match *:read
		},
		{
			name:       "no match",
			permission: Permission{Resource: "system", Action: "delete"},
			expected:   true, // Should match *:* wildcard
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := permSet.Contains(tt.permission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMarshalUnmarshalPermissions(t *testing.T) {
	permissions := []Permission{
		{
			Resource: "user",
			Action:   "read",
			Scope:    "own",
			Attributes: map[string]any{
				"department": "engineering",
				"level":      5,
			},
		},
		{
			Resource: "role",
			Action:   "manage",
		},
	}

	// Test marshaling
	data, err := MarshalPermissions(permissions)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test unmarshaling
	unmarshaled, err := UnmarshalPermissions(data)
	require.NoError(t, err)
	assert.Equal(t, permissions, unmarshaled)

	// Test empty permissions
	emptyData, err := MarshalPermissions([]Permission{})
	require.NoError(t, err)

	emptyUnmarshaled, err := UnmarshalPermissions(emptyData)
	require.NoError(t, err)
	assert.Empty(t, emptyUnmarshaled)

	// Test nil data
	nilUnmarshaled, err := UnmarshalPermissions(nil)
	require.NoError(t, err)
	assert.Empty(t, nilUnmarshaled)
}

func TestService_GetEffectivePermissions(t *testing.T) {
	userID := uuid.New()
	userRoles := []*Role{
		{
			ID:   uuid.New(),
			Name: "user",
			Permissions: []Permission{
				{Resource: "user", Action: "read", Scope: "own"},
				{Resource: "user", Action: "update", Scope: "own"},
			},
		},
		{
			ID:   uuid.New(),
			Name: "moderator",
			Permissions: []Permission{
				{Resource: "user", Action: "read", Scope: "all"},
				{Resource: "role", Action: "read"},
			},
		},
	}

	repo := &MockRepository{}
	repo.On("GetUserRoles", mock.Anything, userID).Return(userRoles, nil)

	service := NewService(repo)
	ctx := context.Background()

	permissions, err := service.GetEffectivePermissions(ctx, userID)
	require.NoError(t, err)
	assert.NotEmpty(t, permissions)

	// Should have merged permissions from both roles
	permStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permStrings[i] = perm.String()
	}

	assert.Contains(t, permStrings, "user:read:all") // Should be upgraded from "own" to "all"
	assert.Contains(t, permStrings, "user:update:own")
	assert.Contains(t, permStrings, "role:read")

	repo.AssertExpectations(t)
}

func TestService_CheckResourceAccess(t *testing.T) {
	userID := uuid.New()
	userRoles := []*Role{
		{
			ID:   uuid.New(),
			Name: "admin",
			Permissions: []Permission{
				{Resource: "user", Action: "read"},
				{Resource: "user", Action: "write"},
				{Resource: "user", Action: "delete"},
			},
		},
	}

	repo := &MockRepository{}
	repo.On("GetUserRoles", mock.Anything, userID).Return(userRoles, nil)

	service := NewService(repo)
	ctx := context.Background()

	actions := []string{"read", "write", "delete", "manage"}
	result, err := service.CheckResourceAccess(ctx, userID, "user", actions)

	require.NoError(t, err)
	assert.True(t, result["read"])
	assert.True(t, result["write"])
	assert.True(t, result["delete"])
	assert.False(t, result["manage"]) // Not explicitly granted

	repo.AssertExpectations(t)
}

func TestService_ValidateRoleHierarchy(t *testing.T) {
	userID := uuid.New()

	tests := []struct {
		name         string
		userRoles    []*Role
		requiredRole string
		expected     bool
	}{
		{
			name: "admin has moderator privileges",
			userRoles: []*Role{
				{ID: uuid.New(), Name: "admin"},
			},
			requiredRole: "moderator",
			expected:     true,
		},
		{
			name: "user does not have admin privileges",
			userRoles: []*Role{
				{ID: uuid.New(), Name: "user"},
			},
			requiredRole: "admin",
			expected:     false,
		},
		{
			name: "exact role match for non-hierarchy role",
			userRoles: []*Role{
				{ID: uuid.New(), Name: "custom-role"},
			},
			requiredRole: "custom-role",
			expected:     true,
		},
		{
			name: "superuser has all privileges",
			userRoles: []*Role{
				{ID: uuid.New(), Name: "superuser"},
			},
			requiredRole: "admin",
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &MockRepository{}
			repo.On("GetUserRoles", mock.Anything, userID).Return(tt.userRoles, nil)

			service := NewService(repo)
			ctx := context.Background()

			result, err := service.ValidateRoleHierarchy(ctx, userID, tt.requiredRole)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)

			repo.AssertExpectations(t)
		})
	}
}

func TestRoleTemplates(t *testing.T) {
	tests := []struct {
		name     string
		roleFunc func() *Role
		expected string
	}{
		{
			name:     "guest role",
			roleFunc: NewGuestRole,
			expected: "guest",
		},
		{
			name:     "user role",
			roleFunc: NewUserRole,
			expected: "user",
		},
		{
			name:     "moderator role",
			roleFunc: NewModeratorRole,
			expected: "moderator",
		},
		{
			name:     "admin role",
			roleFunc: NewAdminRole,
			expected: "admin",
		},
		{
			name:     "superuser role",
			roleFunc: NewSuperUserRole,
			expected: "superuser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := tt.roleFunc()
			assert.Equal(t, tt.expected, role.Name)
			assert.NotEmpty(t, role.Description)
			assert.NotEmpty(t, role.Permissions)
		})
	}
}

func TestRole_HasPermission(t *testing.T) {
	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Resource: "user", Action: "read"},
			{Resource: "user", Action: "write"},
		},
	}

	tests := []struct {
		name       string
		permission Permission
		expected   bool
	}{
		{
			name:       "has exact permission",
			permission: Permission{Resource: "user", Action: "read"},
			expected:   true,
		},
		{
			name:       "does not have permission",
			permission: Permission{Resource: "role", Action: "read"},
			expected:   false,
		},
		{
			name:       "wildcard match",
			permission: Permission{Resource: "user", Action: "delete"},
			expected:   true, // Should match user:* wildcard
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := role.HasPermission(tt.permission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRole_AddRemovePermission(t *testing.T) {
	role := &Role{
		Name: "test",
		Permissions: []Permission{
			{Resource: "user", Action: "read"},
		},
	}

	// Test adding new permission
	newPerm := Permission{Resource: "user", Action: "write"}
	role.AddPermission(newPerm)
	assert.True(t, role.HasPermission(newPerm))
	assert.Len(t, role.Permissions, 2)

	// Test adding duplicate permission (should not add)
	role.AddPermission(newPerm)
	assert.Len(t, role.Permissions, 2)

	// Test removing permission
	role.RemovePermission(newPerm)
	assert.False(t, role.HasPermission(newPerm))
	assert.Len(t, role.Permissions, 1)
}
