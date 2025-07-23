package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// RoleRepository implements role data access using SQLC
type RoleRepository struct {
	queries *db.Queries
}

// NewRoleRepository creates a new role repository using SQLC
func NewRoleRepository(database *DB) *RoleRepository {
	return &RoleRepository{
		queries: db.New(database.Primary()),
	}
}

// CreateRole creates a new role in the database
func (r *RoleRepository) CreateRole(ctx context.Context, roleData *CreateRoleData) (*RoleData, error) {
	params := db.CreateRoleParams{
		Name:        roleData.Name,
		Description: pgtype.Text{String: roleData.Description, Valid: roleData.Description != ""},
		// Permissions: roleData.Permissions, //TODO: Handle convert
	}

	role, err := r.queries.CreateRole(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	return r.convertToRoleData(role), nil
}

// GetRoleByID retrieves a role by ID
func (r *RoleRepository) GetRoleByID(ctx context.Context, roleID string) (*RoleData, error) {
	id, err := uuid.Parse(roleID)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID format: %w", err)
	}

	role, err := r.queries.GetRoleByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Role not found
		}
		return nil, fmt.Errorf("failed to get role by ID: %w", err)
	}

	return r.convertToRoleData(role), nil
}

// GetRoleByName retrieves a role by name
func (r *RoleRepository) GetRoleByName(ctx context.Context, name string) (*RoleData, error) {
	role, err := r.queries.GetRoleByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Role not found
		}
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}

	return r.convertToRoleData(role), nil
}

// UpdateRole updates role information
func (r *RoleRepository) UpdateRole(ctx context.Context, roleID string, data *UpdateRoleData) (*RoleData, error) {
	id, err := uuid.Parse(roleID)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID format: %w", err)
	}

	params := db.UpdateRoleParams{
		ID: id,
	}

	// Set fields that are being updated
	if data.Name != nil {
		params.Name = *data.Name
	}
	if data.Description != nil {
		params.Description = pgtype.Text{String: *data.Description, Valid: true}
	}
	// TODO: Handle conversion
	// if data.Permissions != nil {
	// 	params.Permissions = data.Permissions
	// }

	role, err := r.queries.UpdateRole(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	return r.convertToRoleData(role), nil
}

// DeleteRole deletes a role
func (r *RoleRepository) DeleteRole(ctx context.Context, roleID string) error {
	id, err := uuid.Parse(roleID)
	if err != nil {
		return fmt.Errorf("invalid role ID format: %w", err)
	}

	err = r.queries.DeleteRole(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	return nil
}

// ListRoles retrieves roles with pagination
func (r *RoleRepository) ListRoles(ctx context.Context, limit, offset int32) ([]*RoleData, error) {
	params := db.ListRolesParams{
		Limit:  limit,
		Offset: offset,
	}

	roles, err := r.queries.ListRoles(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	result := make([]*RoleData, len(roles))
	for i, role := range roles {
		result[i] = r.convertToRoleData(role)
	}

	return result, nil
}

// CountRoles returns total number of roles
func (r *RoleRepository) CountRoles(ctx context.Context) (int64, error) {
	count, err := r.queries.CountRoles(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count roles: %w", err)
	}

	return count, nil
}

// AssignRoleToUser assigns a role to a user
func (r *RoleRepository) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return fmt.Errorf("invalid role ID format: %w", err)
	}

	params := db.AssignRoleToUserParams{
		UserID: userUUID,
		RoleID: roleUUID,
	}

	err = r.queries.AssignRoleToUser(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}

	return nil
}

// RemoveRoleFromUser removes a role from a user
func (r *RoleRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return fmt.Errorf("invalid role ID format: %w", err)
	}

	params := db.RemoveRoleFromUserParams{
		UserID: userUUID,
		RoleID: roleUUID,
	}

	err = r.queries.RemoveRoleFromUser(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to remove role from user: %w", err)
	}

	return nil
}

// GetUsersByRole retrieves users by role
func (r *RoleRepository) GetUsersByRole(ctx context.Context, roleName string) ([]*UserData, error) {
	users, err := r.queries.GetUsersByRole(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by role: %w", err)
	}

	result := make([]*UserData, len(users))
	for i, user := range users {
		result[i] = r.convertUserToUserData(user)
	}

	return result, nil
}

// convertToRoleData converts SQLC Role model to service RoleData
func (r *RoleRepository) convertToRoleData(role db.Role) *RoleData {
	roleData := &RoleData{
		ID:   role.ID.String(),
		Name: role.Name,
		// Permissions: role.Permissions, TODO: Handle conversion
		CreatedAt: role.CreatedAt.Time.Unix(),
		UpdatedAt: role.UpdatedAt.Time.Unix(),
	}

	// Handle optional description
	if role.Description.Valid {
		roleData.Description = role.Description.String
	}

	return roleData
}

// convertUserToUserData converts SQLC User model to service UserData (for role queries)
func (r *RoleRepository) convertUserToUserData(user db.User) *UserData {
	userData := &UserData{
		ID:                 user.ID.String(),
		Email:              user.Email,
		PasswordHash:       user.PasswordHash,
		HashAlgorithm:      user.HashAlgorithm,
		FirstNameEncrypted: user.FirstNameEncrypted,
		LastNameEncrypted:  user.LastNameEncrypted,
		PhoneEncrypted:     user.PhoneEncrypted,
		CreatedAt:          user.CreatedAt.Time.Unix(),
		UpdatedAt:          user.UpdatedAt.Time.Unix(),
	}

	// Handle optional fields
	if user.Username.Valid {
		userData.Username = user.Username.String
	}
	if user.EmailVerified.Valid {
		userData.EmailVerified = user.EmailVerified.Bool
	}
	if user.PhoneVerified.Valid {
		userData.PhoneVerified = user.PhoneVerified.Bool
	}
	if user.AccountLocked.Valid {
		userData.AccountLocked = user.AccountLocked.Bool
	}
	if user.FailedLoginAttempts.Valid {
		userData.FailedAttempts = user.FailedLoginAttempts.Int32
	}
	if user.LastLoginAt.Valid {
		lastLogin := user.LastLoginAt.Time.Unix()
		userData.LastLoginAt = &lastLogin
	}

	return userData
}

// Data transfer objects for the repository layer
type CreateRoleData struct {
	Name        string
	Description string
	Permissions []string
}

type UpdateRoleData struct {
	Name        *string
	Description *string
	Permissions []string
}

type RoleData struct {
	ID          string
	Name        string
	Description string
	Permissions []string
	CreatedAt   int64
	UpdatedAt   int64
}
