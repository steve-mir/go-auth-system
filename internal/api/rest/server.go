package rest

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/middleware"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
	"github.com/steve-mir/go-auth-system/internal/service/role"
	"github.com/steve-mir/go-auth-system/internal/service/user"
)

// Server represents the REST API server
type Server struct {
	router     *gin.Engine
	server     *http.Server
	config     *config.ServerConfig
	middleware *middleware.MiddlewareManager

	// Service dependencies
	authService auth.AuthService
	userService user.UserService
	roleService role.Service
}

// NewServer creates a new REST API server
func NewServer(
	cfg *config.ServerConfig,
	middlewareManager *middleware.MiddlewareManager,
	authService auth.AuthService,
	userService user.UserService,
	roleService role.Service,
) *Server {
	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	s := &Server{
		router:      router,
		server:      server,
		config:      cfg,
		middleware:  middlewareManager,
		authService: authService,
		userService: userService,
		roleService: roleService,
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s
}

// setupMiddleware configures global middleware
func (s *Server) setupMiddleware() {
	// Recovery middleware (should be first)
	s.router.Use(middleware.RecoveryMiddleware())

	// Request ID middleware
	s.router.Use(middleware.RequestIDMiddleware())

	// Logging middleware
	s.router.Use(middleware.LoggingMiddleware())

	// CORS middleware
	s.router.Use(middleware.CORSMiddleware())

	// Health check middleware (early exit for health checks)
	s.router.Use(middleware.HealthCheckMiddleware())

	// Metrics middleware
	metricsMiddleware := middleware.NewMetricsMiddleware()
	s.router.Use(metricsMiddleware.Handler())
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Root endpoint
	s.router.GET("/", s.rootHandler)

	// Health endpoints
	s.router.GET("/health", s.healthHandler)
	s.router.GET("/health/live", s.livenessHandler)
	s.router.GET("/health/ready", s.readinessHandler)

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// Apply security middleware to all API routes
		v1.Use(s.middleware.CombinedSecurityHandler())

		// Authentication routes (public)
		authGroup := v1.Group("/auth")
		s.setupAuthRoutes(authGroup)

		// Protected routes (require authentication)
		protected := v1.Group("")
		protected.Use(s.authenticationMiddleware())
		{
			// User routes
			userGroup := protected.Group("/users")
			s.setupUserRoutes(userGroup)

			// Role routes
			roleGroup := protected.Group("/roles")
			s.setupRoleRoutes(roleGroup)

			// Admin routes (require admin role)
			adminGroup := protected.Group("/admin")
			adminGroup.Use(s.adminAuthorizationMiddleware())
			s.setupAdminRoutes(adminGroup)
		}
	}
}

// Start starts the REST API server
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("REST API server starting on %s\n", s.server.Addr)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("REST API server failed: %w", err)
	}

	return nil
}

// Stop stops the REST API server
func (s *Server) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// rootHandler handles requests to the root path
func (s *Server) rootHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "go-auth-system",
		"version": "1.0.0",
		"status":  "running",
		"api": gin.H{
			"version":  "v1",
			"base_url": "/api/v1",
			"endpoints": gin.H{
				"auth":  "/api/v1/auth",
				"users": "/api/v1/users",
				"roles": "/api/v1/roles",
				"admin": "/api/v1/admin",
			},
		},
		"health": gin.H{
			"health":    "/health",
			"liveness":  "/health/live",
			"readiness": "/health/ready",
		},
	})
}

// healthHandler handles health check requests
func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "go-auth-system",
	})
}

// livenessHandler handles liveness probe requests
func (s *Server) livenessHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "alive",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// readinessHandler handles readiness probe requests
func (s *Server) readinessHandler(c *gin.Context) {
	// TODO: Check if all critical components are ready
	// For now, we'll assume ready if the server is running
	c.JSON(http.StatusOK, gin.H{
		"status":    "ready",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
