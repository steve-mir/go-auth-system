package rest

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/middleware"

	// "github.com/steve-mir/go-auth-system/internal/service/admin"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
	// "github.com/steve-mir/go-auth-system/internal/service/role"
	// "github.com/steve-mir/go-auth-system/internal/service/user"
)

// Server represents the REST API server
type Server struct {
	router     *gin.Engine
	server     *http.Server
	config     *config.ServerConfig
	middleware *middleware.MiddlewareManager

	// Service dependencies
	adminService  interfaces.AdminService
	authService   auth.AuthService
	userService   interfaces.UserService
	roleService   interfaces.RoleService
	healthService HealthService
	ssoService    SSOService
}

// HealthService interface for health checks
type HealthService interface {
	Handler() http.HandlerFunc
	LivenessHandler() http.HandlerFunc
	ReadinessHandler() http.HandlerFunc
}

// SSOService interface for single sign-on operations
type SSOService interface {
	GetOAuthURL(ctx context.Context, provider string, state string) (string, error)
	HandleOAuthCallback(ctx context.Context, provider, code, state string) (*OAuthResult, error)
	UnlinkSocialAccount(ctx context.Context, userID string, provider string) error
	GetLinkedAccounts(ctx context.Context, userID string) ([]LinkedAccount, error)
	GetSAMLMetadata(ctx context.Context) ([]byte, error)
	InitiateSAMLLogin(ctx context.Context, idpEntityID string, relayState string) (*SAMLAuthRequest, error)
	HandleSAMLResponse(ctx context.Context, samlResponse string, relayState string) (*SAMLResult, error)
	GetOIDCAuthURL(ctx context.Context, provider string, state string, nonce string) (string, error)
	HandleOIDCCallback(ctx context.Context, provider, code, state string) (*OIDCResult, error)
	ValidateOIDCIDToken(ctx context.Context, provider, idToken string) (*OIDCIDTokenClaims, error)
	RefreshOIDCToken(ctx context.Context, provider, refreshToken string) (*OIDCTokenResponse, error)
}

// OAuthResult represents OAuth authentication result
type OAuthResult struct {
	UserID       string            `json:"user_id"`
	Email        string            `json:"email"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	IsNewUser    bool              `json:"is_new_user"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	ExpiresAt    int64             `json:"expires_at"`
	Metadata     map[string]string `json:"metadata"`
}

// LinkedAccount represents a linked social account
type LinkedAccount struct {
	Provider string `json:"provider"`
	SocialID string `json:"social_id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	LinkedAt int64  `json:"linked_at"`
}

// SAMLAuthRequest represents a SAML authentication request
type SAMLAuthRequest struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	RelayState  string `json:"relay_state"`
	IDPEntityID string `json:"idp_entity_id"`
	CreatedAt   int64  `json:"created_at"`
}

// SAMLResult represents SAML authentication result
type SAMLResult struct {
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email"`
	Name         string                 `json:"name"`
	NameID       string                 `json:"name_id"`
	SessionIndex string                 `json:"session_index"`
	IDPEntityID  string                 `json:"idp_entity_id"`
	IsNewUser    bool                   `json:"is_new_user"`
	Attributes   map[string]interface{} `json:"attributes"`
	ExpiresAt    int64                  `json:"expires_at"`
}

// OIDCResult represents OIDC authentication result
type OIDCResult struct {
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email"`
	Name         string                 `json:"name"`
	Subject      string                 `json:"subject"`
	Provider     string                 `json:"provider"`
	IsNewUser    bool                   `json:"is_new_user"`
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	IDToken      string                 `json:"id_token"`
	ExpiresAt    int64                  `json:"expires_at"`
	Claims       map[string]interface{} `json:"claims"`
}

// OIDCIDTokenClaims represents OIDC ID token claims
type OIDCIDTokenClaims struct {
	Subject   string `json:"subject"`
	Email     string `json:"email"`
	ExpiresAt int64  `json:"expires_at"`
}

// OIDCTokenResponse represents OIDC token response
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

// NewServer creates a new REST API server
func NewServer(
	cfg *config.ServerConfig,
	middlewareManager *middleware.MiddlewareManager,
	authService auth.AuthService,
	userService interfaces.UserService,
	roleService interfaces.RoleService,
	adminService interfaces.AdminService,
	healthService HealthService,
	ssoService SSOService,
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
		router:        router,
		server:        server,
		config:        cfg,
		middleware:    middlewareManager,
		authService:   authService,
		userService:   userService,
		roleService:   roleService,
		adminService:  adminService,
		healthService: healthService,
		ssoService:    ssoService,
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s
}

// setupMiddleware configures global middleware
func (s *Server) setupMiddleware() {
	// Recovery middleware (should be first)
	s.router.Use(gin.Recovery())

	// Request ID middleware
	s.router.Use(func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	})

	// Logging middleware
	s.router.Use(gin.Logger())

	// CORS middleware
	s.router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Apply middleware manager if available
	if s.middleware != nil {
		// Apply rate limiting and security middleware to API routes only
		// This will be applied in setupRoutes for specific route groups
	}
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

		// OAuth/SSO routes (public)
		s.setupOAuthRoutes(v1)

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

			//TODO: Admin routes (require admin role)
			// adminGroup := protected.Group("/admin")
			// adminGroup.Use(s.adminAuthorizationMiddleware())
			// s.setupAdminRoutes(adminGroup)
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
	if s.healthService != nil {
		s.healthService.Handler()(c.Writer, c.Request)
		return
	}

	// Fallback if health service is not available
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "go-auth-system",
	})
}

// livenessHandler handles liveness probe requests
func (s *Server) livenessHandler(c *gin.Context) {
	if s.healthService != nil {
		s.healthService.LivenessHandler()(c.Writer, c.Request)
		return
	}

	// Fallback if health service is not available
	c.JSON(http.StatusOK, gin.H{
		"status":    "alive",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// readinessHandler handles readiness probe requests
func (s *Server) readinessHandler(c *gin.Context) {
	if s.healthService != nil {
		s.healthService.ReadinessHandler()(c.Writer, c.Request)
		return
	}

	// Fallback if health service is not available
	c.JSON(http.StatusOK, gin.H{
		"status":    "ready",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// requireAuth returns a middleware that requires authentication
func (s *Server) requireAuth() gin.HandlerFunc {
	return s.authenticationMiddleware()
}

func generateRequestID() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int63())
}
