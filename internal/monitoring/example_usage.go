package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/health"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres"
)

// ExampleUsage demonstrates how to set up and use the monitoring system
func ExampleUsage() {
	// 1. Create monitoring configuration
	monitoringConfig := Config{
		Enabled: true,
		Prometheus: PrometheusConfig{
			Enabled: true,
			Path:    "/metrics",
			Port:    9090,
		},
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	// 2. Initialize monitoring service
	monitoringService, err := NewService(monitoringConfig)
	if err != nil {
		panic(fmt.Sprintf("Failed to create monitoring service: %v", err))
	}

	// 3. Start metrics collection
	ctx := context.Background()
	monitoringService.StartCollection(ctx, 30*time.Second)

	// 4. Set up health checks with monitoring integration
	healthService := health.NewService()
	healthService.SetMonitoring(monitoringService)

	// Add database health checker (example)
	// db := postgres.NewDB(dbConfig) // Your database connection
	// healthService.AddChecker(health.NewDatabaseChecker(db))

	// Add Redis health checker (example)
	// redisClient := redis.NewClient(&redis.Options{...}) // Your Redis client
	// healthService.AddChecker(health.NewRedisChecker(redisClient))

	// Add liveness and readiness checkers
	healthService.AddChecker(health.NewLivenessChecker())
	// healthService.AddChecker(health.NewReadinessChecker(...))

	// 5. Set up HTTP server with monitoring middleware
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Add monitoring middleware
	router.Use(RequestIDMiddleware())
	router.Use(TraceIDMiddleware())
	router.Use(monitoringService.HTTPMiddleware())

	// Health check endpoints
	router.GET("/health", func(c *gin.Context) {
		health := healthService.Check(c.Request.Context())
		status := http.StatusOK
		if health.Status == "unhealthy" {
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, health)
	})

	router.GET("/health/live", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "alive"})
	})

	router.GET("/health/ready", func(c *gin.Context) {
		health := healthService.Check(c.Request.Context())
		status := http.StatusOK
		if health.Status != "healthy" {
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, gin.H{"status": "ready"})
	})

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(monitoringService.MetricsHandler()))

	// Example API endpoints with monitoring
	router.POST("/api/auth/login", func(c *gin.Context) {
		start := time.Now()

		// Simulate authentication logic
		userID := "user123"
		method := "password"
		success := true // This would be determined by actual auth logic

		// Record authentication event
		details := map[string]interface{}{
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
		}

		monitoringService.RecordAuthEvent(
			c.Request.Context(),
			method,
			userID,
			success,
			time.Since(start),
			details,
		)

		if success {
			c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Login failed"})
		}
	})

	router.POST("/api/users", func(c *gin.Context) {
		// Simulate user registration
		userID := "user456"
		details := map[string]interface{}{
			"method": "direct",
		}

		monitoringService.RecordUserEvent(
			c.Request.Context(),
			"register",
			userID,
			details,
		)

		c.JSON(http.StatusCreated, gin.H{"message": "User created"})
	})

	// 6. Example of recording custom metrics
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Update system metrics
				monitoringService.UpdateActiveSessions("web", 150)
				monitoringService.UpdateActiveSessions("mobile", 75)
				monitoringService.UpdateDatabaseConnections(8, 2, 10)
			}
		}
	}()

	// 7. Start HTTP server
	fmt.Println("Starting server with monitoring on :8080")
	fmt.Println("Metrics available at http://localhost:8080/metrics")
	fmt.Println("Health check at http://localhost:8080/health")

	// In a real application, you would start the server here
	// router.Run(":8080")
}

// ExampleDatabaseMonitoring shows how to monitor database operations
func ExampleDatabaseMonitoring(monitoringService *Service) {
	// Example of using database middleware
	dbMiddleware := monitoringService.DatabaseMiddleware()

	// Wrap database operations
	err := dbMiddleware("SELECT", "users", func() error {
		// Your actual database query here
		time.Sleep(50 * time.Millisecond) // Simulate query time
		return nil
	})

	if err != nil {
		fmt.Printf("Database operation failed: %v\n", err)
	}
}

// ExampleCacheMonitoring shows how to monitor cache operations
func ExampleCacheMonitoring(monitoringService *Service) {
	// Example of using cache middleware
	cacheMiddleware := monitoringService.CacheMiddleware()
	ctx := context.Background()

	// Wrap cache operations
	hit, err := cacheMiddleware(ctx, "redis", "get", "user:123", func() (bool, error) {
		// Your actual cache operation here
		time.Sleep(5 * time.Millisecond) // Simulate cache lookup
		return true, nil                 // Cache hit
	})

	if err != nil {
		fmt.Printf("Cache operation failed: %v\n", err)
	} else if hit {
		fmt.Println("Cache hit!")
	} else {
		fmt.Println("Cache miss!")
	}
}

// ExampleAuthMonitoring shows how to monitor authentication operations
func ExampleAuthMonitoring(monitoringService *Service) {
	// Example of using auth middleware
	authMiddleware := monitoringService.AuthMiddleware()
	ctx := context.Background()

	// Wrap authentication operations
	err := authMiddleware(ctx, "password", "user123", func() error {
		// Your actual authentication logic here
		time.Sleep(100 * time.Millisecond) // Simulate auth time
		return nil                         // Successful authentication
	})

	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
	} else {
		fmt.Println("Authentication successful!")
	}
}

// ExampleCustomMetrics shows how to record custom metrics and events
func ExampleCustomMetrics(monitoringService *Service) {
	ctx := context.Background()

	// Record various types of events

	// 1. Authentication events
	monitoringService.RecordAuthEvent(ctx, "oauth", "user123", true, 150*time.Millisecond, map[string]interface{}{
		"provider": "google",
		"ip":       "192.168.1.1",
	})

	// 2. Token events
	monitoringService.RecordTokenEvent(ctx, "generate", "jwt", true, map[string]interface{}{
		"user_id": "user123",
	})

	// 3. MFA events
	monitoringService.RecordMFAEvent(ctx, "totp", true, "", map[string]interface{}{
		"user_id": "user123",
	})

	// 4. Security events
	monitoringService.RecordSecurityEvent(ctx, "suspicious_login", "medium", map[string]interface{}{
		"ip":           "192.168.1.100",
		"failed_count": 5,
	})

	// 5. Audit events
	monitoringService.RecordAuditEvent(ctx, "update_profile", "user", "user123", map[string]interface{}{
		"field":     "email",
		"old_value": "old@example.com",
		"new_value": "new@example.com",
	})

	// 6. Rate limiting events
	monitoringService.RecordRateLimitEvent(ctx, "ip", "192.168.1.1", false, map[string]interface{}{
		"limit":  100,
		"window": "1m",
	})
}

// ExampleHealthCheckIntegration shows how to integrate health checks with monitoring
func ExampleHealthCheckIntegration(db *postgres.DB, redisClient *redis.Client) *health.Service {
	// Create monitoring service
	config := Config{
		Enabled: true,
		Logging: LoggerConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
			Output: "stdout",
		},
	}

	monitoringService, err := NewService(config)
	if err != nil {
		panic(err)
	}

	// Create health service
	healthService := health.NewService()
	healthService.SetMonitoring(monitoringService)

	// Add health checkers
	healthService.AddChecker(health.NewLivenessChecker())
	healthService.AddChecker(health.NewDatabaseChecker(db))
	healthService.AddChecker(health.NewRedisChecker(redisClient))

	// Create readiness checker that depends on database and Redis
	readinessChecker := health.NewReadinessChecker(
		health.NewDatabaseChecker(db),
		health.NewRedisChecker(redisClient),
	)
	healthService.AddChecker(readinessChecker)

	return healthService
}

// ExampleConfigurationFromFile shows how to load monitoring configuration from file
func ExampleConfigurationFromFile() (*Service, error) {
	// Load application configuration
	appConfig, err := config.Load("config.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Extract monitoring configuration
	monitoringConfig := Config{
		Enabled:    appConfig.External.Monitoring.Enabled,
		Prometheus: PrometheusConfig(appConfig.External.Monitoring.Prometheus),
		Logging:    LoggerConfig(appConfig.External.Logging),
	}

	// Create monitoring service
	return NewService(monitoringConfig)
}
