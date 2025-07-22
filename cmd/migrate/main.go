package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
)

func main() {
	var (
		configPath = flag.String("config", "", "Path to configuration file")
		command    = flag.String("command", "up", "Migration command: up, down, status")
		timeout    = flag.Duration("timeout", 30*time.Second, "Migration timeout")
	)
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create database connection
	db, err := postgres.NewConnection(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create migration manager
	migrationManager := postgres.NewMigrationManager(db)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Execute migration command
	switch *command {
	case "up":
		if err := migrationManager.MigrateUp(ctx); err != nil {
			log.Fatalf("Migration up failed: %v", err)
		}
		fmt.Println("All migrations applied successfully")

	case "down":
		if err := migrationManager.MigrateDown(ctx); err != nil {
			log.Fatalf("Migration down failed: %v", err)
		}
		fmt.Println("Migration rolled back successfully")

	case "status":
		status, err := migrationManager.GetMigrationStatus(ctx)
		if err != nil {
			log.Fatalf("Failed to get migration status: %v", err)
		}

		fmt.Println("Migration Status:")
		fmt.Println("================")
		for _, s := range status {
			appliedStatus := "Pending"
			appliedTime := ""
			if s.Applied {
				appliedStatus = "Applied"
				if s.AppliedAt != nil {
					appliedTime = fmt.Sprintf(" (%s)", s.AppliedAt.Format("2006-01-02 15:04:05"))
				}
			}
			fmt.Printf("Version %d: %s - %s%s\n", s.Version, s.Name, appliedStatus, appliedTime)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", *command)
		fmt.Fprintf(os.Stderr, "Available commands: up, down, status\n")
		os.Exit(1)
	}
}
