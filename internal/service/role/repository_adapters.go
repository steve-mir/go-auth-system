package role

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// PostgresRepository implements the Repository interface using PostgreSQL
type PostgresRepository struct {
	queries *postgres.DB
	store   *db.Store
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(queries *postgres.DB, store *db.Store) Repository {
	return &PostgresRepository{
		queries: queries,
		store:   store,
	}
}

// CreateRole creates a new role in the database
func (r *PostgresRepository) CreateRole(ctx context.Context, role *Role) error {
	permissionsJSON, err := MarshalPermissions(role.Permissions)
	if err != nil {
		return err
	}

	dbRole, err := r.store.CreateRole(ctx, db.CreateRoleParams{
		Name:        role.Name,
		Description: pgtype.Text{String: role.Description, Valid: role.Description != ""},
		Permissions: permissionsJSON,
	})
	if err != nil {
		return err
	}

	// Update the role with generated values
	role.ID = dbRole.ID
	role.CreatedAt = dbRole.CreatedAt.Time
	role.UpdatedAt = dbRole.UpdatedAt.Time

	return nil
}

// GetRoleByID retrieves a role by its ID
func (r *PostgresRepository) GetRoleByID(ctx context.Context, roleID uuid.UUID) (*Role, error) {
	dbRole, err := r.store.GetRoleByID(ctx, roleID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, NewRoleNotFoundError(roleID.String())
		}
		return nil, err
	}

	return r.dbRoleToRole(dbRole)
}

// GetRoleByName retrieves a role by its name
func (r *PostgresRepository) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	dbRole, err := r.store.GetRoleByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, NewRoleNotFoundError(name)
		}
		return nil, err
	}

	return r.dbRoleToRole(dbRole)
}

// UpdateRole updates an existing role
func (r *PostgresRepository) UpdateRole(ctx context.Context, role *Role) error {
	permissionsJSON, err := MarshalPermissions(role.Permissions)
	if err != nil {
		return err
	}

	dbRole, err := r.store.UpdateRole(ctx, db.UpdateRoleParams{
		ID:          role.ID,
		Name:        role.Name,
		Description: pgtype.Text{String: role.Description, Valid: true},
		Permissions: permissionsJSON,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return NewRoleNotFoundError(role.ID.String())
		}
		return err
	}

	// Update the role with new values
	role.UpdatedAt = dbRole.UpdatedAt.Time

	return nil
}

// DeleteRole deletes a role by its ID
func (r *PostgresRepository) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	err := r.store.DeleteRole(ctx, roleID)
	if err != nil {
		return err
	}
	return nil
}

// ListRoles retrieves a paginated list of roles
func (r *PostgresRepository) ListRoles(ctx context.Context, limit, offset int) ([]*Role, error) {
	dbRoles, err := r.store.ListRoles(ctx, db.ListRolesParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, err
	}

	roles := make([]*Role, len(dbRoles))
	for i, dbRole := range dbRoles {
		role, err := r.dbRoleToRole(dbRole)
		if err != nil {
			return nil, err
		}
		roles[i] = role
	}

	return roles, nil
}

// CountRoles returns the total number of roles
func (r *PostgresRepository) CountRoles(ctx context.Context) (int64, error) {
	count, err := r.store.CountRoles(ctx)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// AssignRoleToUser assigns a role to a user
func (r *PostgresRepository) AssignRoleToUser(ctx context.Context, userID, roleID, assignedBy uuid.UUID) error {
	err := r.store.AssignRoleToUser(ctx, db.AssignRoleToUserParams{
		UserID:     userID,
		RoleID:     roleID,
		AssignedBy: pgtype.UUID{Bytes: assignedBy, Valid: true},
	})
	return err
}

// RemoveRoleFromUser removes a role from a user
func (r *PostgresRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	err := r.store.RemoveRoleFromUser(ctx, db.RemoveRoleFromUserParams{
		UserID: userID,
		RoleID: roleID,
	})
	return err
}

// GetUserRoles retrieves all roles assigned to a user
func (r *PostgresRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error) {
	dbRoles, err := r.store.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	roles := make([]*Role, len(dbRoles))
	for i, dbRole := range dbRoles {
		role, err := r.dbRoleToRole(dbRole)
		if err != nil {
			return nil, err
		}
		roles[i] = role
	}

	return roles, nil
}

// GetRoleUsers retrieves all users assigned to a role
func (r *PostgresRepository) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]*UserInfo, error) {
	dbUsers, err := r.store.GetRoleUsers(ctx, roleID)
	if err != nil {
		return nil, err
	}

	users := make([]*UserInfo, len(dbUsers))
	for i, dbUser := range dbUsers {
		users[i] = &UserInfo{
			ID:        dbUser.ID,
			Email:     dbUser.Email,
			Username:  dbUser.Username.String,
			CreatedAt: dbUser.CreatedAt.Time,
		}
	}

	return users, nil
}

// dbRoleToRole converts a database role to a service role
func (r *PostgresRepository) dbRoleToRole(dbRole db.Role) (*Role, error) {
	permissions, err := UnmarshalPermissions(dbRole.Permissions)
	if err != nil {
		return nil, err
	}

	return &Role{
		ID:          dbRole.ID,
		Name:        dbRole.Name,
		Description: dbRole.Description.String,
		Permissions: permissions,
		CreatedAt:   dbRole.CreatedAt.Time,
		UpdatedAt:   dbRole.UpdatedAt.Time,
	}, nil
}
