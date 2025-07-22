package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/health"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	"github.com/steve-mir/go-auth-system/internal/server"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Config Path: %s.Failed to load configuration: %v", configPath, err)
	}

	// Print configuration summary
	printConfigSummary(cfg)

	// Initialize application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, gracefully shutting down...")
		cancel()
	}()

	// Initialize and start server (placeholder for now)
	if err := runServer(ctx, cfg); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

	log.Println("Server shutdown complete")
}

// printConfigSummary prints a summary of the loaded configuration
func printConfigSummary(cfg *config.Config) {
	fmt.Printf("Go Auth System Server\n")
	fmt.Printf("=====================\n")
	fmt.Printf("Server: %s:%d\n", cfg.Server.Host, cfg.Server.Port)
	fmt.Printf("gRPC: %s:%d\n", cfg.Server.Host, cfg.Server.GRPCPort)
	fmt.Printf("Database: %s@%s:%d/%s\n", cfg.Database.User, cfg.Database.Host, cfg.Database.Port, cfg.Database.Name)
	fmt.Printf("Redis: %s:%d (DB: %d)\n", cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.DB)
	fmt.Printf("Password Hash: %s\n", cfg.Security.PasswordHash.Algorithm)
	fmt.Printf("Token Type: %s\n", cfg.Security.Token.Type)
	fmt.Printf("Rate Limiting: %t\n", cfg.Security.RateLimit.Enabled)
	fmt.Printf("MFA: %t\n", cfg.Features.MFA.Enabled)
	fmt.Printf("Admin Dashboard: %t\n", cfg.Features.AdminDashboard.Enabled)
	fmt.Printf("Audit Logging: %t\n", cfg.Features.AuditLogging.Enabled)
	fmt.Printf("Monitoring: %t\n", cfg.External.Monitoring.Enabled)
	fmt.Printf("\nConfiguration loaded successfully!\n")
}

// runServer initializes and runs the server
func runServer(ctx context.Context, cfg *config.Config) error {
	log.Printf("Initializing go-auth-system server...")

	// Initialize database connection
	log.Printf("Connecting to database...")
	db, err := postgres.NewConnection(&cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()
	log.Printf("Database connection established")

	// Run database migrations
	log.Printf("Running database migrations...")
	migrationManager := postgres.NewMigrationManager(db)
	if err := migrationManager.MigrateUp(ctx); err != nil {
		log.Printf("Migration warning: %v", err)
		// Don't fail startup on migration errors in case they're already applied
	} else {
		log.Printf("Database migrations completed successfully")
	}

	// Initialize health service
	healthSvc := health.NewService()

	// Add database health checker
	dbChecker := health.NewDatabaseChecker(db)
	healthSvc.AddChecker(dbChecker)

	// Add liveness checker
	livenessChecker := health.NewLivenessChecker()
	healthSvc.AddChecker(livenessChecker)

	// Add readiness checker
	readinessChecker := health.NewReadinessChecker(dbChecker)
	healthSvc.AddChecker(readinessChecker)

	log.Printf("Health checks initialized")

	// Initialize HTTP server
	httpServer := server.NewHTTPServer(&cfg.Server, healthSvc)

	// Start servers
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// Start HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := httpServer.Start(ctx); err != nil {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	log.Printf("HTTP server started on %s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Health endpoints available:")
	log.Printf("  - Health: http://%s:%d/health", cfg.Server.Host, cfg.Server.Port)
	log.Printf("  - Liveness: http://%s:%d/health/live", cfg.Server.Host, cfg.Server.Port)
	log.Printf("  - Readiness: http://%s:%d/health/ready", cfg.Server.Host, cfg.Server.Port)

	// TODO: Initialize Redis connection
	// TODO: Initialize security services (hash, token, encryption)
	// TODO: Initialize business services (auth, user, role)
	// TODO: Initialize gRPC server

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		log.Printf("Shutdown signal received, stopping servers...")
	case err := <-errChan:
		log.Printf("Server error: %v", err)
		return err
	}

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Stop(shutdownCtx); err != nil {
		log.Printf("Error stopping HTTP server: %v", err)
	}

	wg.Wait()
	log.Printf("All servers stopped")

	return nil
}
