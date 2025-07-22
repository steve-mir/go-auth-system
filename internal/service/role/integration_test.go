//go:build integration
// +build integration

package role

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

type RoleServiceIntegrationTestSuite struct {
	suite.Suite
	db      *sql.DB
	queries *db.Queries
	service Service
	ctx     context.Context
}

func (suite *RoleServiceIntegrationTestSuite) SetupSuite() {
	// This would typically connect to a test database
	// For now, we'll skip the actual database connection
	suite.ctx = context.Background()
}

func (suite *RoleServiceIntegrationTestSuite) SetupTest() {
	// Clean up any existing test data
	// This would typically truncate tables or use transactions
}

func (suite *RoleServiceIntegrationTestSuite) TearDownTest() {
	// Clean up test data
}

func (suite *RoleServiceIntegrationTestSuite) TestCreateAndGetRole() {
	if suite.db == nil {
		suite.T().Skip("Database not available for integration test")
		return
	}

	// Create a role
	req := CreateRoleRequest{
		Name:        "test-admin",
		Description: "Test administrator role",
		Permissions: []Permission{
			{Resource: "user", Action: "read", Scope: "all"},
			{Resource: "user", Action: "write", Scope: "all"},
			{Resource: "role", Action: "manage"},
		},
	}

	role, err := suite.service.CreateRole(suite.ctx, req)
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), role)

	assert.Equal(suite.T(), req.Name, role.Name)
	assert.Equal(suite.T(), req.Description, role.Description)
	assert.Equal(suite.T(), req.Permissions, role.Permissions)
	assert.NotEqual(suite.T(), uuid.Nil, role.ID)

	// Get the role back
	retrievedRole, err := suite.service.GetRole(suite.ctx, role.ID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), role.ID, retrievedRole.ID)
	assert.Equal(suite.T(), role.Name, retrievedRole.Name)
	assert.Equal(suite.T(), role.Description, retrievedRole.Description)
	assert.Equal(suite.T(), role.Permissions, retrievedRole.Permissions)

	// Get role by name
	roleByName, err := suite.service.GetRoleByName(suite.ctx, role.Name)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), role.ID, roleByName.ID)
}

func (suite *RoleServiceIntegrationTestSuite) TestUpdateRole() {
	if suite.db == nil {
		suite.T().Skip("Database not available for integration test")
		return
	}

	// Create a role first
	req := CreateRoleRequest{
		Name:        "test-user",
		Description: "Test user role",
		Permissions: []Permission{
			{Resource: "user", Action: "read", Scope: "own"},
		},
	}

	role, err := suite.service.CreateRole(suite.ctx, req)
	require.NoError(suite.T(), err)

	// Update the role
	newName := "test-power-user"
	newDescription := "Test power user role"
	newPermissions := []Permission{
		{Resource: "user", Action: "read", Scope: "own"},
		{Resource: "user", Action: "update", Scope: "own"},
	}

	updateReq := UpdateRoleRequest{
		Name:        &newName,
		Description: &newDescription,
		Permissions: newPermissions,
	}

	updatedRole, err := suite.service.UpdateRole(suite.ctx, role.ID, updateReq)
	require.NoError(suite.T(), err)

	assert.Equal(suite.T(), newName, updatedRole.Name)
	assert.Equal(suite.T(), newDescription, updatedRole.Description)
	assert.Equal(suite.T(), newPermissions, updatedRole.Permissions)
}

func (suite *RoleServiceIntegrationTestSuite) TestListRoles() {
	if suite.db == nil {
		suite.T().Skip("Database not available for integration test")
		return
	}

	// Create multiple roles
	roles := []CreateRoleRequest{
		{Name: "admin", Description: "Administrator"},
		{Name: "user", Description: "Regular user"},
		{Name: "moderator", Description: "Moderator"},
	}

	createdRoles := make([]*Role, len(roles))
	for i, req := range roles {
		role, err := suite.service.CreateRole(suite.ctx, req)
		require.NoError(suite.T(), err)
		createdRoles[i] = role
	}

	// List roles
	listReq := ListRolesRequest{Limit: 10, Offset: 0}
	response, err := suite.service.ListRoles(suite.ctx, listReq)
	require.NoError(suite.T(), err)

	assert.GreaterOrEqual(suite.T(), len(response.Roles), 3)
	assert.GreaterOrEqual(suite.T(), response.Total, int64(3))
}

func (suite *RoleServiceIntegrationTestSuite) TestRoleUserAssignment() {
	if suite.db == nil {
		suite.T().Skip("Database not available for integration test")
		return
	}

	// Create a role
	req := CreateRoleRequest{
		Name:        "test-assignment",
		Description: "Test role for assignment",
		Permissions: []Permission{
			{Resource: "user", Action: "read", Scope: "own"},
		},
	}

	role, err := suite.service.CreateRole(suite.ctx, req)
	require.NoError(suite.T(), err)

	// Create mock user IDs
	userID := uuid.New()
	assignedBy := uuid.New()

	// Assign role to user
	err = suite.service.AssignRoleToUser(suite.ctx, userID, role.ID, assignedBy)
	require.NoError(suite.T(), err)

	// Get user roles
	userRoles, err := suite.service.GetUserRoles(suite.ctx, userID)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), userRoles, 1)
	assert.Equal(suite.T(), role.ID, userRoles[0].ID)

	// Remove role from user
	err = suite.service.RemoveRoleFromUser(suite.ctx, userID, role.ID)
	require.NoError(suite.T(), err)

	// Verify role is removed
	userRoles, err = suite.service.GetUserRoles(suite.ctx, userID)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), userRoles, 0)
}

func (suite *RoleServiceIntegrationTestSuite) TestPermissionValidation() {
	if suite.db == nil {
		suite.T().Skip("Database not available for integration test")
		return
	}

	// Create a role with specific permissions
	req := CreateRoleRequest{
		Name:        "test-permissions",
		Description: "Test role for permission validation",
		Permissions: []Permission{
			{Resource: "user", Action: "read", Scope: "all"},
			{Resource: "user", Action: "update", Scope: "own"},
			{Resource: "role", Action: "read"},
		},
	}

	role, err := suite.service.CreateRole(suite.ctx, req)
	require.NoError(suite.T(), err)

	// Create mock user and assign role
	userID := uuid.New()
	assignedBy := uuid.New()

	err = suite.service.AssignRoleToUser(suite.ctx, userID, role.ID, assignedBy)
	require.NoError(suite.T(), err)

	// Test permission validation
	tests := []struct {
		permission Permission
		expected   bool
	}{
		{
			permission: Permission{Resource: "user", Action: "read", Scope: "all"},
			expected:   true,
		},
		{
			permission: Permission{Resource: "user", Action: "update", Scope: "own"},
			expected:   true,
		},
		{
			permission: Permission{Resource: "role", Action: "read"},
			expected:   true,
		},
		{
			permission: Permission{Resource: "user", Action: "delete", Scope: "all"},
			expected:   false,
		},
		{
			permission: Permission{Resource: "system", Action: "manage"},
			expected:   false,
		},
	}

	for _, test := range tests {
		hasPermission, err := suite.service.ValidatePermission(suite.ctx, userID, test.permission)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), test.expected, hasPermission,
			"Permission %s should be %v", test.permission.String(), test.expected)
	}
}

func (suite *RoleServiceIntegrationTestSuite) TestAccessValidation() {
	if suite.db == nil {
		suite.T().Skip("Database not available for integration test")
		return
	}

	// Create a role with attribute-based permissions
	req := CreateRoleRequest{
		Name:        "test-abac",
		Description: "Test role for ABAC",
		Permissions: []Permission{
			{
				Resource: "document",
				Action:   "read",
				Scope:    "own",
				Attributes: map[string]interface{}{
					"department": "engineering",
					"clearance":  "confidential",
				},
			},
			{
				Resource: "user",
				Action:   "read",
				Scope:    "all",
			},
		},
	}

	role, err := suite.service.CreateRole(suite.ctx, req)
	require.NoError(suite.T(), err)

	// Create mock user and assign role
	userID := uuid.New()
	assignedBy := uuid.New()

	err = suite.service.AssignRoleToUser(suite.ctx, userID, role.ID, assignedBy)
	require.NoError(suite.T(), err)

	// Test access validation
	tests := []struct {
		name     string
		request  AccessRequest
		expected bool
	}{
		{
			name: "valid attribute-based access",
			request: AccessRequest{
				UserID:   userID,
				Resource: "document",
				Action:   "read",
				Scope:    "own",
				Attributes: map[string]interface{}{
					"department": "engineering",
					"clearance":  "confidential",
				},
			},
			expected: true,
		},
		{
			name: "invalid department attribute",
			request: AccessRequest{
				UserID:   userID,
				Resource: "document",
				Action:   "read",
				Scope:    "own",
				Attributes: map[string]interface{}{
					"department": "marketing",
					"clearance":  "confidential",
				},
			},
			expected: false,
		},
		{
			name: "basic permission without attributes",
			request: AccessRequest{
				UserID:   userID,
				Resource: "user",
				Action:   "read",
				Scope:    "all",
			},
			expected: true,
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

	for _, test := range tests {
		suite.T().Run(test.name, func(t *testing.T) {
			response, err := suite.service.ValidateAccess(suite.ctx, test.request)
			require.NoError(t, err)
			assert.Equal(t, test.expected, response.Allowed)
		})
	}
}

func TestRoleServiceIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(RoleServiceIntegrationTestSuite))
}
