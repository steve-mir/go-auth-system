//go:build integration
// +build integration

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/health"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
)

// Simple integration test to verify our health check implementation
func main() {
	fmt.Println("Running integration test for health checks...")

	// Load default configuration
	cfg := &config.Config{}

	// Set basic defaults for testing
	cfg.Database.Host = "localhost"
	cfg.Database.Port = 5432
	cfg.Database.Name = "auth_system"
	cfg.Database.User = "postgres"
	cfg.Database.Password = "postgres"
	cfg.Database.SSLMode = "disable"
	cfg.Database.MaxOpenConns = 5
	cfg.Database.MaxIdleConns = 2
	cfg.Database.ConnMaxLifetime = 5 * time.Minute
	cfg.Database.ConnMaxIdleTime = 5 * time.Minute
	cfg.Database.ConnectTimeout = 10

	// Test database connection (this will fail if PostgreSQL is not running)
	fmt.Println("Testing database connection...")
	db, err := postgres.NewConnection(&cfg.Database)
	if err != nil {
		log.Printf("Database connection failed (expected if PostgreSQL is not running): %v", err)
		fmt.Println("Skipping database health check test")
	} else {
		defer db.Close()
		fmt.Println("Database connection successful!")

		// Test database health checker
		fmt.Println("Testing database health checker...")
		dbChecker := health.NewDatabaseChecker(db)
		ctx := context.Background()
		healthResult := dbChecker.Check(ctx)

		fmt.Printf("Database health check result: %s - %s\n", healthResult.Status, healthResult.Message)
	}

	// Test liveness checker
	fmt.Println("Testing liveness checker...")
	livenessChecker := health.NewLivenessChecker()
	ctx := context.Background()
	livenessResult := livenessChecker.Check(ctx)
	fmt.Printf("Liveness check result: %s - %s\n", livenessResult.Status, livenessResult.Message)

	// Test health service
	fmt.Println("Testing health service...")
	healthSvc := health.NewService()
	healthSvc.AddChecker(livenessChecker)

	if db != nil {
		dbChecker := health.NewDatabaseChecker(db)
		healthSvc.AddChecker(dbChecker)
	}

	overallHealth := healthSvc.Check(ctx)
	fmt.Printf("Overall health status: %s\n", overallHealth.Status)
	fmt.Printf("Components checked: %d\n", len(overallHealth.Components))

	for name, component := range overallHealth.Components {
		fmt.Printf("  - %s: %s (%s)\n", name, component.Status, component.Message)
	}

	// Test HTTP handler
	fmt.Println("Testing HTTP health handler...")
	handler := healthSvc.Handler()

	// Create a test server
	server := &http.Server{
		Addr:    ":8888",
		Handler: http.HandlerFunc(handler),
	}

	go func() {
		fmt.Println("Starting test HTTP server on :8888...")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Test server error: %v", err)
		}
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Test the health endpoint
	resp, err := http.Get("http://localhost:8888")
	if err != nil {
		log.Printf("Failed to call health endpoint: %v", err)
	} else {
		fmt.Printf("Health endpoint responded with status: %d\n", resp.StatusCode)
		resp.Body.Close()
	}

	// Shutdown test server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)

	fmt.Println("Integration test completed successfully!")
}
