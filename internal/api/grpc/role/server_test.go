package role

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/steve-mir/go-auth-system/internal/service/role"
	"github.com/steve-mir/go-auth-system/pb"
)

// MockRoleService is a mock implementation of role.Service
type MockRoleService struct {
	mock.Mock
}

func (m *MockRoleService) CreateRole(ctx context.Context, req role.CreateRoleRequest) (*role.Role, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*role.Role), args.Error(1)
}

func (m *MockRoleService) GetRole(ctx context.Context, roleID uuid.UUID) (*role.Role, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*role.Role), args.Error(1)
}

func (m *MockRoleService) GetRoleByName(ctx context.Context, name string) (*role.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*role.Role), args.Error(1)
}

func (m *MockRoleService) UpdateRole(ctx context.Context, roleID uuid.UUID, req role.UpdateRoleRequest) (*role.Role, error) {
	args := m.Called(ctx, roleID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*role.Role), args.Error(1)
}

func (m *MockRoleService) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func (m *MockRoleService) ListRoles(ctx context.Context, req role.ListRolesRequest) (*role.ListRolesResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*role.ListRolesResponse), args.Error(1)
}

func (m *MockRoleService) AssignRoleToUser(ctx context.Context, userID, roleID, assignedBy uuid.UUID) error {
	args := m.Called(ctx, userID, roleID, assignedBy)
	return args.Error(0)
}

func (m *MockRoleService) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockRoleService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*role.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*role.Role), args.Error(1)
}

func (m *MockRoleService) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*role.UserInfo, error) {
	args := m.Called(ctx, roleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*role.UserInfo), args.Error(1)
}

func (m *MockRoleService) ValidatePermission(ctx context.Context, userID uuid.UUID, permission role.Permission) (bool, error) {
	args := m.Called(ctx, userID, permission)
	return args.Bool(0), args.Error(1)
}

func (m *MockRoleService) ValidatePermissions(ctx context.Context, userID uuid.UUID, permissions []role.Permission) (map[string]bool, error) {
	args := m.Called(ctx, userID, permissions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]bool), args.Error(1)
}

func (m *MockRoleService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]role.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]role.Permission), args.Error(1)
}

func (m *MockRoleService) ValidateAccess(ctx context.Context, req role.AccessRequest) (*role.AccessResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*role.AccessResponse), args.Error(1)
}

func (m *MockRoleService) GetEffectivePermissions(ctx context.Context, userID uuid.UUID) ([]role.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]role.Permission), args.Error(1)
}

func (m *MockRoleService) CheckResourceAccess(ctx context.Context, userID uuid.UUID, resource string, actions []string) (map[string]bool, error) {
	args := m.Called(ctx, userID, resource, actions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]bool), args.Error(1)
}

func (m *MockRoleService) ValidateRoleHierarchy(ctx context.Context, userID uuid.UUID, requiredRole string) (bool, error) {
	args := m.Called(ctx, userID, requiredRole)
	return args.Bool(0), args.Error(1)
}

func TestServer_CreateRole(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.CreateRoleRequest
		mockSetup      func(*MockRoleService)
		expectedError  bool
		expectedCode   codes.Code
		validateResult func(*testing.T, *pb.CreateRoleResponse)
	}{
		{
			name: "successful role creation",
			request: &pb.CreateRoleRequest{
				Name:        "test-role",
				Description: "Test role description",
				Permissions: []string{"user:read", "user:write"},
			},
			mockSetup: func(m *MockRoleService) {
				roleID := uuid.New()
				now := time.Now()

				m.On("CreateRole", mock.Anything, mock.MatchedBy(func(req role.CreateRoleRequest) bool {
					return req.Name == "test-role" &&
						req.Description == "Test role description" &&
						len(req.Permissions) == 2
				})).Return(&role.Role{
					ID:          roleID,
					Name:        "test-role",
					Description: "Test role description",
					Permissions: []role.Permission{
						{Resource: "user", Action: "read"},
						{Resource: "user", Action: "write"},
					},
					CreatedAt: now,
					UpdatedAt: now,
				}, nil)
			},
			expectedError: false,
			validateResult: func(t *testing.T, resp *pb.CreateRoleResponse) {
				assert.NotNil(t, resp.Role)
				assert.Equal(t, "test-role", resp.Role.Name)
				assert.Equal(t, "Test role description", resp.Role.Description)
				assert.Len(t, resp.Role.Permissions, 2)
				assert.Contains(t, resp.Role.Permissions, "user:read")
				assert.Contains(t, resp.Role.Permissions, "user:write")
			},
		},
		{
			name: "missing role name",
			request: &pb.CreateRoleRequest{
				Name:        "",
				Description: "Test role description",
			},
			mockSetup:     func(m *MockRoleService) {},
			expectedError: true,
			expectedCode:  codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockRoleService{}
			tt.mockSetup(mockService)

			server := NewServer(mockService)
			ctx := context.Background()

			resp, err := server.CreateRole(ctx, tt.request)

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

func TestServer_ValidatePermission(t *testing.T) {
	tests := []struct {
		name           string
		request        *pb.ValidatePermissionRequest
		mockSetup      func(*MockRoleService)
		expectedError  bool
		expectedCode   codes.Code
		validateResult func(*testing.T, *pb.ValidatePermissionResponse)
	}{
		{
			name: "permission allowed",
			request: &pb.ValidatePermissionRequest{
				UserId:   "user-123",
				Resource: "user",
				Action:   "read",
				Scope:    "own",
			},
			mockSetup: func(m *MockRoleService) {
				userID, _ := uuid.Parse("user-123")
				m.On("ValidatePermission", mock.Anything, userID, mock.MatchedBy(func(perm role.Permission) bool {
					return perm.Resource == "user" && perm.Action == "read" && perm.Scope == "own"
				})).Return(true, nil)
			},
			expectedError: false,
			validateResult: func(t *testing.T, resp *pb.ValidatePermissionResponse) {
				assert.True(t, resp.Allowed)
				assert.Equal(t, "Permission granted", resp.Reason)
			},
		},
		{
			name: "permission denied",
			request: &pb.ValidatePermissionRequest{
				UserId:   "user-123",
				Resource: "admin",
				Action:   "delete",
			},
			mockSetup: func(m *MockRoleService) {
				userID, _ := uuid.Parse("user-123")
				m.On("ValidatePermission", mock.Anything, userID, mock.MatchedBy(func(perm role.Permission) bool {
					return perm.Resource == "admin" && perm.Action == "delete"
				})).Return(false, nil)
			},
			expectedError: false,
			validateResult: func(t *testing.T, resp *pb.ValidatePermissionResponse) {
				assert.False(t, resp.Allowed)
				assert.Equal(t, "Permission denied", resp.Reason)
			},
		},
		{
			name: "missing user_id",
			request: &pb.ValidatePermissionRequest{
				UserId:   "",
				Resource: "user",
				Action:   "read",
			},
			mockSetup:     func(m *MockRoleService) {},
			expectedError: true,
			expectedCode:  codes.InvalidArgument,
		},
		{
			name: "invalid user_id format",
			request: &pb.ValidatePermissionRequest{
				UserId:   "invalid-uuid",
				Resource: "user",
				Action:   "read",
			},
			mockSetup:     func(m *MockRoleService) {},
			expectedError: true,
			expectedCode:  codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockRoleService{}
			tt.mockSetup(mockService)

			server := NewServer(mockService)
			ctx := context.Background()

			resp, err := server.ValidatePermission(ctx, tt.request)

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
