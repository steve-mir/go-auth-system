package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/steve-mir/go-auth-system/internal/api/rest"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/health"
	"github.com/steve-mir/go-auth-system/internal/middleware"
	"github.com/steve-mir/go-auth-system/internal/monitoring"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
	sqlc "github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
	"github.com/steve-mir/go-auth-system/internal/repository/redis"
	"github.com/steve-mir/go-auth-system/internal/security/crypto"
	"github.com/steve-mir/go-auth-system/internal/security/hash"
	"github.com/steve-mir/go-auth-system/internal/security/token"
	"github.com/steve-mir/go-auth-system/internal/service/admin"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
	"github.com/steve-mir/go-auth-system/internal/service/role"
	"github.com/steve-mir/go-auth-system/internal/service/sso"
	"github.com/steve-mir/go-auth-system/internal/service/user"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Config Path: %s. Failed to load configuration: %v", configPath, err)
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

	// Initialize and start server
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

// runServer initializes and runs the server with core components
func runServer(ctx context.Context, cfg *config.Config) error {
	log.Printf("Initializing go-auth-system server...")

	// Initialize monitoring service first
	var monitoringSvc *monitoring.Service
	if cfg.External.Monitoring.Enabled {
		log.Printf("Initializing monitoring service...")
		monitoringConfig := monitoring.Config{
			Enabled: cfg.External.Monitoring.Enabled,
			Prometheus: monitoring.PrometheusConfig{
				Enabled: cfg.External.Monitoring.Prometheus.Enabled,
				Path:    cfg.External.Monitoring.Prometheus.Path,
				Port:    cfg.External.Monitoring.Prometheus.Port,
			},
			Logging: monitoring.LoggerConfig{
				Level:  monitoring.LogLevel(cfg.External.Logging.Level),
				Format: monitoring.LogFormat(cfg.External.Logging.Format),
				Output: cfg.External.Logging.Output,
			},
		}

		var err error
		monitoringSvc, err = monitoring.NewService(monitoringConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize monitoring service: %w", err)
		}

		// Start metrics collection
		monitoringSvc.StartCollection(ctx, 30*time.Second)
		log.Printf("Monitoring service initialized")
	}

	// Initialize database connection
	log.Printf("Connecting to database...")
	db, err := postgres.NewConnection(&cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()
	log.Printf("Database connection established")

	// Update monitoring with database health
	if monitoringSvc != nil {
		monitoringSvc.UpdateSystemHealth("database", true)
	}

	// Run database migrations
	log.Printf("Running database migrations...")
	migrationManager := postgres.NewMigrationManager(db)
	if err := migrationManager.MigrateUp(ctx); err != nil {
		log.Printf("Migration warning: %v", err)
		// Don't fail startup on migration errors in case they're already applied
	} else {
		log.Printf("Database migrations completed successfully")
	}

	// Initialize Redis connection
	log.Printf("Connecting to Redis...")
	redisClient, err := redis.NewClient(&cfg.Redis)
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	defer redisClient.Close()
	log.Printf("Redis connection established")

	// Update monitoring with Redis health
	if monitoringSvc != nil {
		monitoringSvc.UpdateSystemHealth("redis", true)
	}

	// Initialize security services
	log.Printf("Initializing security services...")

	// Hash service factory
	hashFactory := hash.NewFactory(cfg.Security.PasswordHash)
	if err := hashFactory.ValidateConfig(); err != nil {
		return fmt.Errorf("invalid hash configuration: %w", err)
	}

	hashSvc, err := hashFactory.CreateHashService()
	if err != nil {
		return fmt.Errorf("failed to create hash service: %w", err)
	}

	// Token service factory
	tokenFactory := token.NewFactory(&cfg.Security.Token)
	tokenSvc, err := tokenFactory.CreateTokenService()
	if err != nil {
		return fmt.Errorf("failed to create token service: %w", err)
	}

	// Encryptor service factory
	encryptorFactory := crypto.NewEncryptionServiceFactory(&crypto.EncryptionConfig{
		Algorithm:     "aes-256-gcm",
		KeySize:       32,
		MasterKey:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // TODO: Use proper key management
		KeyRotation:   false,
		KeyManagement: "local",
	})
	encryptorSvc, err := encryptorFactory.CreateEncryptionService()
	if err != nil {
		return fmt.Errorf("failed to create encryptor service: %w", err)
	}

	log.Printf("Security services initialized (Hash: %s, Token: %s)",
		cfg.Security.PasswordHash.Algorithm, cfg.Security.Token.Type)

	// Initialize middleware
	log.Printf("Initializing middleware...")
	middlewareConfig := middleware.DefaultConfig()
	middlewareConfig.RateLimit.UserWindow = cfg.Security.RateLimit.WindowSize

	// config.RateLimit.GlobalLimit = 1000
	// config.RateLimit.IPLimit = 100
	// config.Security.BlockedIPs = []string{"192.168.1.100"}

	// middlewareConfig := &middleware.Config{
	// 	RateLimit: &middleware.RateLimitConfig{
	// 		Enabled:        cfg.Security.RateLimit.Enabled,
	// 		RequestsPerMin: cfg.Security.RateLimit.RequestsPerMin,
	// 		BurstSize:      cfg.Security.RateLimit.BurstSize,
	// 		UserWindow:     cfg.Security.RateLimit.WindowSize,
	// 	},
	// 	Security: middleware.DefaultSecurityConfig(),
	// }

	middlewareManager := middleware.NewMiddlewareManager(middlewareConfig, redisClient)
	log.Printf("Middleware initialized (Rate Limiting: %t)", cfg.Security.RateLimit.Enabled)

	// Initialize health service
	log.Printf("Initializing health service...")
	healthSvc := health.NewService()

	// Add health checkers
	dbChecker := health.NewDatabaseChecker(db)
	healthSvc.AddChecker(dbChecker)

	redisChecker := health.NewRedisChecker(redisClient)
	healthSvc.AddChecker(redisChecker)

	livenessChecker := health.NewLivenessChecker()
	healthSvc.AddChecker(livenessChecker)

	readinessChecker := health.NewReadinessChecker(dbChecker, redisChecker)
	healthSvc.AddChecker(readinessChecker)

	log.Printf("Health checks initialized")

	// Initialize repositories
	log.Printf("Initializing repositories...")

	store := sqlc.NewStore(db.Primary())
	authUserRepo := auth.NewPostgresUserRepository(db, store)
	roleRepo := role.NewPostgresRepository(db, store)
	userRepo := user.NewPostgresUserRepository(db, store)
	redisStore := redis.NewSessionStore(redisClient)
	sessionStore := auth.NewRedisSessionRepository(redisStore)
	redisBlacklist := redis.NewTokenBlacklist(redisClient)
	blacklistRepo := auth.NewRedisTokenBlacklistRepository(redisBlacklist)

	log.Printf("Repositories initialized")

	// Initialize business services
	log.Printf("Initializing business services...")

	// Initialize auth service with dependencies
	authDeps := &auth.Dependencies{
		UserRepo:      authUserRepo,
		SessionRepo:   sessionStore,
		BlacklistRepo: blacklistRepo,
		TokenService:  tokenSvc,
		HashService:   hashSvc,
		Encryptor:     encryptorSvc.GetEncryptor(),
	}
	authService := auth.NewAuthService(cfg, authDeps)

	// Initialize user service
	userService := user.NewService(&user.Dependencies{
		UserRepo:    userRepo,
		SessionRepo: sessionStore,
		AuditRepo:   user.NewPostgresAuditRepository(db, store),
		HashService: hashSvc,
		Encryptor:   encryptorSvc.GetEncryptor(),
	})

	// Initialize role service
	roleService := role.NewService(roleRepo)

	// Initialize admin service
	adminService := admin.NewService(admin.Dependencies{
		Config:      cfg,
		UserService: userService,
		RoleService: roleService,
		// SessionRepo: sessionStore,
		// AuditService      audit.AuditService
		// MonitoringService *monitoring.Service
		// SessionRepo       SessionRepository
		// AlertRepo         AlertRepository
		// NotificationRepo  NotificationRepository
	})

	// Initialize SSO service
	log.Printf("Initializing SSO service...")
	socialAccountRepo := postgres.NewSocialAccountRepository(store)
	stateStore := sso.NewRedisStateStore(redisClient)

	// Create SSO user repository adapter
	ssoUserRepo := &SSOUserRepositoryAdapter{
		authRepo:  authUserRepo,
		encryptor: encryptorSvc.GetEncryptor(),
	}

	ssoService := sso.NewSSOService(
		cfg,
		ssoUserRepo,
		socialAccountRepo,
		stateStore,
		hashSvc,
		encryptorSvc.GetEncryptor(),
	)
	log.Printf("SSO service initialized")

	log.Printf("Business services initialized")

	// roleService := role.NewRol
	log.Printf("Initializing HTTP server...")
	httpServer := rest.NewServer(
		&cfg.Server,
		middlewareManager,
		authService,
		userService,
		roleService,
		adminService,
		healthSvc,
		ssoService,
	)
	// httpServer := server.NewHTTPServer(&cfg.Server, healthSvc)

	// TODO: Initialize business services and REST API
	// For now, we have a working server with health checks, monitoring, and middleware

	log.Printf("HTTP server initialized")

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

	// Start Prometheus metrics server if enabled
	if cfg.External.Monitoring.Prometheus.Enabled && monitoringSvc != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			metricsAddr := fmt.Sprintf(":%d", cfg.External.Monitoring.Prometheus.Port)
			metricsServer := &http.Server{
				Addr:    metricsAddr,
				Handler: promhttp.Handler(),
			}

			log.Printf("Prometheus metrics server starting on %s", metricsAddr)

			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				metricsServer.Shutdown(shutdownCtx)
			}()

			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("Prometheus metrics server error: %w", err)
			}
		}()
	}

	log.Printf("All servers started successfully!")
	log.Printf("HTTP server: http://%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Health endpoints:")
	log.Printf("  - Health: http://%s:%d/health", cfg.Server.Host, cfg.Server.Port)
	log.Printf("  - Liveness: http://%s:%d/health/live", cfg.Server.Host, cfg.Server.Port)
	log.Printf("  - Readiness: http://%s:%d/health/ready", cfg.Server.Host, cfg.Server.Port)

	if cfg.External.Monitoring.Prometheus.Enabled {
		log.Printf("Prometheus metrics: http://localhost:%d/metrics", cfg.External.Monitoring.Prometheus.Port)
	}

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		log.Printf("Shutdown signal received, stopping servers...")
	case err := <-errChan:
		log.Printf("Server error: %v", err)
		return err
	}

	// Graceful shutdown
	log.Printf("Starting graceful shutdown...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Stop(shutdownCtx); err != nil {
		log.Printf("Error stopping HTTP server: %v", err)
	}

	if monitoringSvc != nil {
		if err := monitoringSvc.Close(); err != nil {
			log.Printf("Error closing monitoring service: %v", err)
		}
	}

	wg.Wait()
	log.Printf("All servers stopped gracefully")

	return nil
}

// SSOUserRepositoryAdapter adapts auth.UserRepository to sso.UserRepository interface
type SSOUserRepositoryAdapter struct {
	authRepo  auth.UserRepository
	encryptor crypto.Encryptor
}

func (a *SSOUserRepositoryAdapter) GetUserByEmail(ctx context.Context, email string) (*sso.UserData, error) {
	authUser, err := a.authRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	return &sso.UserData{
		ID:                 authUser.ID,
		Email:              authUser.Email,
		Username:           authUser.Username,
		PasswordHash:       authUser.PasswordHash,
		HashAlgorithm:      authUser.HashAlgorithm,
		FirstNameEncrypted: authUser.FirstNameEncrypted,
		LastNameEncrypted:  authUser.LastNameEncrypted,
		PhoneEncrypted:     authUser.PhoneEncrypted,
		EmailVerified:      authUser.EmailVerified,
		PhoneVerified:      authUser.PhoneVerified,
		AccountLocked:      authUser.AccountLocked,
		FailedAttempts:     authUser.FailedAttempts,
		LastLoginAt:        authUser.LastLoginAt,
		CreatedAt:          authUser.CreatedAt,
		UpdatedAt:          authUser.UpdatedAt,
	}, nil
}

func (a *SSOUserRepositoryAdapter) CreateUser(ctx context.Context, user *sso.CreateUserData) (*sso.UserData, error) {
	// Encrypt sensitive data
	var firstNameEncrypted, lastNameEncrypted, phoneEncrypted []byte
	var err error

	if user.FirstName != "" {
		firstNameEncrypted, err = a.encryptor.Encrypt([]byte(user.FirstName))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt first name: %w", err)
		}
	}

	if user.LastName != "" {
		lastNameEncrypted, err = a.encryptor.Encrypt([]byte(user.LastName))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt last name: %w", err)
		}
	}

	if user.Phone != "" {
		phoneEncrypted, err = a.encryptor.Encrypt([]byte(user.Phone))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt phone: %w", err)
		}
	}

	authUser := &auth.CreateUserData{
		Email:              user.Email,
		Username:           user.Username,
		PasswordHash:       user.PasswordHash,
		HashAlgorithm:      user.HashAlgorithm,
		FirstNameEncrypted: firstNameEncrypted,
		LastNameEncrypted:  lastNameEncrypted,
		PhoneEncrypted:     phoneEncrypted,
	}

	createdUser, err := a.authRepo.CreateUser(ctx, authUser)
	if err != nil {
		return nil, err
	}

	return &sso.UserData{
		ID:                 createdUser.ID,
		Email:              createdUser.Email,
		Username:           createdUser.Username,
		PasswordHash:       createdUser.PasswordHash,
		HashAlgorithm:      createdUser.HashAlgorithm,
		FirstNameEncrypted: createdUser.FirstNameEncrypted,
		LastNameEncrypted:  createdUser.LastNameEncrypted,
		PhoneEncrypted:     createdUser.PhoneEncrypted,
		EmailVerified:      createdUser.EmailVerified,
		PhoneVerified:      createdUser.PhoneVerified,
		AccountLocked:      createdUser.AccountLocked,
		FailedAttempts:     createdUser.FailedAttempts,
		LastLoginAt:        createdUser.LastLoginAt,
		CreatedAt:          createdUser.CreatedAt,
		UpdatedAt:          createdUser.UpdatedAt,
	}, nil
}

func (a *SSOUserRepositoryAdapter) UpdateUser(ctx context.Context, user *sso.UpdateUserData) error {
	// Encrypt sensitive data if provided
	var firstNameEncrypted, lastNameEncrypted, phoneEncrypted []byte
	var err error

	if user.FirstName != "" {
		firstNameEncrypted, err = a.encryptor.Encrypt([]byte(user.FirstName))
		if err != nil {
			return fmt.Errorf("failed to encrypt first name: %w", err)
		}
	}

	if user.LastName != "" {
		lastNameEncrypted, err = a.encryptor.Encrypt([]byte(user.LastName))
		if err != nil {
			return fmt.Errorf("failed to encrypt last name: %w", err)
		}
	}

	if user.Phone != "" {
		phoneEncrypted, err = a.encryptor.Encrypt([]byte(user.Phone))
		if err != nil {
			return fmt.Errorf("failed to encrypt phone: %w", err)
		}
	}

	authUser := &auth.UpdateUserData{
		ID:                 user.ID,
		Username:           user.Username,
		FirstNameEncrypted: firstNameEncrypted,
		LastNameEncrypted:  lastNameEncrypted,
		PhoneEncrypted:     phoneEncrypted,
	}

	return a.authRepo.UpdateUser(ctx, authUser)
}
