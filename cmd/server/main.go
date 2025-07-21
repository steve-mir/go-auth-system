package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/steve-mir/go-auth-system/internal/config"
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
	log.Printf("Starting server on %s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Starting gRPC server on %s:%d", cfg.Server.Host, cfg.Server.GRPCPort)

	// TODO: Initialize database connection
	// TODO: Initialize Redis connection
	// TODO: Initialize security services (hash, token, encryption)
	// TODO: Initialize business services (auth, user, role)
	// TODO: Initialize API servers (REST, gRPC)
	// TODO: Start servers

	// For now, just wait for context cancellation
	<-ctx.Done()
	return nil
}
