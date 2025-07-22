package main

// import (
// 	"context"
// 	"database/sql"
// 	"embed"
// 	"fmt"
// 	"path/filepath"
// 	"sort"
// 	"strconv"
// 	"strings"
// 	"time"

// 	"github.com/jackc/pgx/v5/stdlib"
// 	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
// )

// //go:embed sql/migrations/*.sql
// var migrationFiles embed.FS

// // Migration represents a database migration
// type Migration struct {
// 	Version     int
// 	Name        string
// 	UpScript    string
// 	DownScript  string
// 	AppliedAt   *time.Time
// 	Description string
// }

// // MigrationManager handles database migrations
// type MigrationManager struct {
// 	db *postgres.DB
// }

// // NewMigrationManager creates a new migration manager
// func NewMigrationManager(db *postgres.DB) *MigrationManager {
// 	return &MigrationManager{db: db}
// }

// // InitMigrationTable creates the migration tracking table if it doesn't exist
// func (m *MigrationManager) InitMigrationTable(ctx context.Context) error {
// 	query := `
// 		CREATE TABLE IF NOT EXISTS schema_migrations (
// 			version INTEGER PRIMARY KEY,
// 			name VARCHAR(255) NOT NULL,
// 			applied_at TIMESTAMP NOT NULL DEFAULT NOW(),
// 			description TEXT
// 		);

// 		CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at
// 		ON schema_migrations(applied_at);
// 	`

// 	_, err := m.db.Exec(ctx, query)
// 	if err != nil {
// 		return fmt.Errorf("failed to create migration table: %w", err)
// 	}

// 	return nil
// }

// // LoadMigrations loads all migration files from the embedded filesystem
// func (m *MigrationManager) LoadMigrations() ([]Migration, error) {
// 	entries, err := migrationFiles.ReadDir("sql/migrations")
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read migration directory: %w", err)
// 	}

// 	migrationMap := make(map[int]*Migration)

// 	for _, entry := range entries {
// 		if entry.IsDir() {
// 			continue
// 		}

// 		filename := entry.Name()
// 		if !strings.HasSuffix(filename, ".sql") {
// 			continue
// 		}

// 		version, name, direction, err := parseMigrationFilename(filename)
// 		if err != nil {
// 			continue // Skip invalid filenames
// 		}

// 		content, err := migrationFiles.ReadFile(filepath.Join("sql/migrations", filename))
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to read migration file %s: %w", filename, err)
// 		}

// 		if migrationMap[version] == nil {
// 			migrationMap[version] = &Migration{
// 				Version: version,
// 				Name:    name,
// 			}
// 		}

// 		if direction == "up" {
// 			migrationMap[version].UpScript = string(content)
// 		} else {
// 			migrationMap[version].DownScript = string(content)
// 		}
// 	}

// 	// Convert map to slice and sort by version
// 	var migrations []Migration
// 	for _, migration := range migrationMap {
// 		if migration.UpScript != "" { // Only include migrations with up scripts
// 			migrations = append(migrations, *migration)
// 		}
// 	}

// 	sort.Slice(migrations, func(i, j int) bool {
// 		return migrations[i].Version < migrations[j].Version
// 	})

// 	return migrations, nil
// }

// // GetAppliedMigrations returns all applied migrations from the database
// func (m *MigrationManager) GetAppliedMigrations(ctx context.Context) (map[int]Migration, error) {
// 	query := `
// 		SELECT version, name, applied_at, description
// 		FROM schema_migrations
// 		ORDER BY version ASC
// 	`

// 	rows, err := m.db.Query(ctx, query)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
// 	}
// 	defer rows.Close()

// 	applied := make(map[int]Migration)

// 	for rows.Next() {
// 		var migration Migration
// 		var appliedAt time.Time
// 		var description sql.NullString

// 		err := rows.Scan(&migration.Version, &migration.Name, &appliedAt, &description)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to scan migration row: %w", err)
// 		}

// 		migration.AppliedAt = &appliedAt
// 		if description.Valid {
// 			migration.Description = description.String
// 		}

// 		applied[migration.Version] = migration
// 	}

// 	if err := rows.Err(); err != nil {
// 		return nil, fmt.Errorf("error iterating migration rows: %w", err)
// 	}

// 	return applied, nil
// }

// // MigrateUp applies all pending migrations
// func (m *MigrationManager) MigrateUp(ctx context.Context) error {
// 	if err := m.InitMigrationTable(ctx); err != nil {
// 		return err
// 	}

// 	migrations, err := m.LoadMigrations()
// 	if err != nil {
// 		return err
// 	}

// 	applied, err := m.GetAppliedMigrations(ctx)
// 	if err != nil {
// 		return err
// 	}

// 	for _, migration := range migrations {
// 		if _, exists := applied[migration.Version]; exists {
// 			continue // Skip already applied migrations
// 		}

// 		if err := m.applyMigration(ctx, migration); err != nil {
// 			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
// 		}

// 		fmt.Printf("Applied migration %d: %s\n", migration.Version, migration.Name)
// 	}

// 	return nil
// }

// // MigrateDown rolls back the last applied migration
// func (m *MigrationManager) MigrateDown(ctx context.Context) error {
// 	applied, err := m.GetAppliedMigrations(ctx)
// 	if err != nil {
// 		return err
// 	}

// 	if len(applied) == 0 {
// 		return fmt.Errorf("no migrations to rollback")
// 	}

// 	// Find the highest version migration
// 	var lastMigration Migration
// 	maxVersion := 0
// 	for version, migration := range applied {
// 		if version > maxVersion {
// 			maxVersion = version
// 			lastMigration = migration
// 		}
// 	}

// 	migrations, err := m.LoadMigrations()
// 	if err != nil {
// 		return err
// 	}

// 	// Find the migration with down script
// 	var targetMigration *Migration
// 	for _, migration := range migrations {
// 		if migration.Version == lastMigration.Version {
// 			targetMigration = &migration
// 			break
// 		}
// 	}

// 	if targetMigration == nil || targetMigration.DownScript == "" {
// 		return fmt.Errorf("no down script found for migration %d", lastMigration.Version)
// 	}

// 	if err := m.rollbackMigration(ctx, *targetMigration); err != nil {
// 		return fmt.Errorf("failed to rollback migration %d: %w", targetMigration.Version, err)
// 	}

// 	fmt.Printf("Rolled back migration %d: %s\n", targetMigration.Version, targetMigration.Name)
// 	return nil
// }

// // applyMigration applies a single migration
// func (m *MigrationManager) applyMigration(ctx context.Context, migration Migration) error {
// 	// Start transaction
// 	tx, err := m.db.Begin(ctx)
// 	if err != nil {
// 		return fmt.Errorf("failed to start transaction: %w", err)
// 	}
// 	defer tx.Rollback(ctx)

// 	// Execute migration script
// 	_, err = tx.Exec(ctx, migration.UpScript)
// 	if err != nil {
// 		return fmt.Errorf("failed to execute migration script: %w", err)
// 	}

// 	// Record migration in tracking table
// 	_, err = tx.Exec(ctx, `
// 		INSERT INTO schema_migrations (version, name, description)
// 		VALUES ($1, $2, $3)
// 	`, migration.Version, migration.Name, migration.Description)
// 	if err != nil {
// 		return fmt.Errorf("failed to record migration: %w", err)
// 	}

// 	// Commit transaction
// 	if err := tx.Commit(ctx); err != nil {
// 		return fmt.Errorf("failed to commit migration transaction: %w", err)
// 	}

// 	return nil
// }

// // rollbackMigration rolls back a single migration
// func (m *MigrationManager) rollbackMigration(ctx context.Context, migration Migration) error {
// 	// Start transaction
// 	tx, err := m.db.Begin(ctx)
// 	if err != nil {
// 		return fmt.Errorf("failed to start transaction: %w", err)
// 	}
// 	defer tx.Rollback(ctx)

// 	// Execute rollback script
// 	_, err = tx.Exec(ctx, migration.DownScript)
// 	if err != nil {
// 		return fmt.Errorf("failed to execute rollback script: %w", err)
// 	}

// 	// Remove migration record
// 	_, err = tx.Exec(ctx, `
// 		DELETE FROM schema_migrations WHERE version = $1
// 	`, migration.Version)
// 	if err != nil {
// 		return fmt.Errorf("failed to remove migration record: %w", err)
// 	}

// 	// Commit transaction
// 	if err := tx.Commit(ctx); err != nil {
// 		return fmt.Errorf("failed to commit rollback transaction: %w", err)
// 	}

// 	return nil
// }

// // GetMigrationStatus returns the current migration status
// func (m *MigrationManager) GetMigrationStatus(ctx context.Context) ([]MigrationStatus, error) {
// 	migrations, err := m.LoadMigrations()
// 	if err != nil {
// 		return nil, err
// 	}

// 	applied, err := m.GetAppliedMigrations(ctx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var status []MigrationStatus
// 	for _, migration := range migrations {
// 		s := MigrationStatus{
// 			Version: migration.Version,
// 			Name:    migration.Name,
// 			Applied: false,
// 		}

// 		if appliedMigration, exists := applied[migration.Version]; exists {
// 			s.Applied = true
// 			s.AppliedAt = appliedMigration.AppliedAt
// 		}

// 		status = append(status, s)
// 	}

// 	return status, nil
// }

// // MigrationStatus represents the status of a migration
// type MigrationStatus struct {
// 	Version   int
// 	Name      string
// 	Applied   bool
// 	AppliedAt *time.Time
// }

// // parseMigrationFilename parses a migration filename to extract version, name, and direction
// // Expected format: 001_migration_name.up.sql or 001_migration_name.down.sql
// func parseMigrationFilename(filename string) (version int, name, direction string, err error) {
// 	// Remove .sql extension
// 	name = strings.TrimSuffix(filename, ".sql")

// 	// Split by dots to get direction
// 	parts := strings.Split(name, ".")
// 	if len(parts) != 2 {
// 		return 0, "", "", fmt.Errorf("invalid migration filename format: %s", filename)
// 	}

// 	direction = parts[1]
// 	if direction != "up" && direction != "down" {
// 		return 0, "", "", fmt.Errorf("invalid migration direction: %s", direction)
// 	}

// 	// Split the first part to get version and name
// 	nameParts := strings.SplitN(parts[0], "_", 2)
// 	if len(nameParts) != 2 {
// 		return 0, "", "", fmt.Errorf("invalid migration filename format: %s", filename)
// 	}

// 	version, err = strconv.Atoi(nameParts[0])
// 	if err != nil {
// 		return 0, "", "", fmt.Errorf("invalid migration version: %s", nameParts[0])
// 	}

// 	name = nameParts[1]
// 	return version, name, direction, nil
// }

// // CreateStdlibDB creates a database/sql compatible DB from pgx connection
// func (db *postgres.DB) CreateStdlibDB() *sql.DB {
// 	return stdlib.OpenDBFromPool(db.Pool)
// }
