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
	"github.com/steve-mir/go-auth-system/internal/monitoring"

	// "github.com/steve-mir/go-auth-system/internal/service/admin"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
	"github.com/steve-mir/go-auth-system/internal/service/mfa"
	// "github.com/steve-mir/go-auth-system/internal/service/role"
	// "github.com/steve-mir/go-auth-system/internal/service/user"
)

// Server represents the REST API server
type Server struct {
	router     *gin.Engine
	server     *http.Server
	config     *config.ServerConfig
	middleware *middleware.MiddlewareManager

	// Monitoring service
	monitoring *monitoring.Service

	// Service dependencies
	adminService  interfaces.AdminService
	authService   auth.AuthService
	userService   interfaces.UserService
	roleService   interfaces.RoleService
	mfaService    mfa.MFAService
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
	monitoringService *monitoring.Service,
	authService auth.AuthService,
	userService interfaces.UserService,
	roleService interfaces.RoleService,
	mfaService mfa.MFAService,
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
		monitoring:    monitoringService,
		authService:   authService,
		userService:   userService,
		roleService:   roleService,
		mfaService:    mfaService,
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

	// Monitoring middleware (early in the chain for comprehensive tracking)
	if s.monitoring != nil {
		// Request ID and correlation middleware
		s.router.Use(s.monitoring.CorrelationMiddleware())

		// HTTP request monitoring middleware
		s.router.Use(s.monitoring.HTTPMiddleware())

		// Tracing middleware for distributed tracing
		s.router.Use(s.monitoring.TracingMiddleware())

		// Error tracking middleware
		s.router.Use(s.monitoring.ErrorTrackingMiddleware())

		// Log aggregation middleware
		s.router.Use(s.monitoring.LogAggregationMiddleware())
	} else {
		// Fallback request ID middleware if monitoring is not available
		s.router.Use(func(c *gin.Context) {
			requestID := c.GetHeader("X-Request-ID")
			if requestID == "" {
				requestID = generateRequestID()
			}
			c.Header("X-Request-ID", requestID)
			c.Set("request_id", requestID)
			c.Next()
		})
	}

	// Replace default Gin logger with our monitoring-aware logger
	if s.monitoring != nil {
		// Custom logger that integrates with monitoring
		s.router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
			// Log through monitoring service for structured logging
			s.monitoring.RecordHTTPEvent(
				context.Background(),
				param.Method,
				param.Path,
				param.StatusCode,
				param.Latency,
				int64(len(param.Request.Header.Get("Content-Length"))),
				int64(param.BodySize),
				param.Request.UserAgent(),
				param.ClientIP,
			)
			return ""
		}))
	} else {
		// Fallback to default Gin logger
		s.router.Use(gin.Logger())
	}

	// CORS middleware
	s.router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Request-ID, X-Trace-ID")

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

	// Monitoring endpoints (if monitoring is enabled)
	if s.monitoring != nil {
		s.setupMonitoringRoutes()
	}

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

			// MFA routes
			s.setupMFARoutes(protected)

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
				"mfa":   "/api/v1/mfa",
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

// setupMonitoringRoutes configures monitoring and observability endpoints
func (s *Server) setupMonitoringRoutes() {
	// Monitoring endpoints group
	monitoring := s.router.Group("/monitoring")
	{
		// Metrics endpoint (Prometheus format)
		monitoring.GET("/metrics", gin.WrapH(s.monitoring.MetricsHandler()))

		// Health check with detailed monitoring info
		monitoring.GET("/health", s.monitoringHealthHandler)

		// System metrics and statistics
		monitoring.GET("/stats", s.systemStatsHandler)

		// Error tracking endpoints
		monitoring.GET("/errors", s.errorsHandler)
		monitoring.GET("/errors/:id", s.errorDetailsHandler)
		monitoring.POST("/errors/:id/resolve", s.resolveErrorHandler)

		// Log aggregation endpoints
		monitoring.GET("/logs", s.logsHandler)
		monitoring.GET("/logs/search", s.searchLogsHandler)
		monitoring.GET("/logs/patterns", s.logPatternsHandler)
		monitoring.GET("/logs/stats", s.logStatsHandler)

		// Alerts endpoints
		monitoring.GET("/alerts", s.alertsHandler)
		monitoring.POST("/alerts/rules", s.createAlertRuleHandler)
		monitoring.DELETE("/alerts/rules/:id", s.deleteAlertRuleHandler)

		// Tracing endpoints
		monitoring.GET("/traces", s.tracesHandler)
		monitoring.GET("/traces/:id", s.traceDetailsHandler)
	}
}

// monitoringHealthHandler provides detailed health information with monitoring data
func (s *Server) monitoringHealthHandler(c *gin.Context) {
	ctx := c.Request.Context()

	// Start monitoring this request
	trace, ctx := s.monitoring.StartTrace(ctx, "monitoring_health_check")
	defer s.monitoring.FinishTrace(ctx, trace, nil)

	// Perform health check
	err := s.monitoring.HealthCheck(ctx)
	if err != nil {
		s.monitoring.TrackError(ctx, err, monitoring.CategorySystem, "health_check", "monitoring")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":    "unhealthy",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"monitoring": gin.H{
			"enabled": true,
			"components": gin.H{
				"metrics":        s.monitoring.GetMetrics() != nil,
				"logging":        s.monitoring.GetLogger() != nil,
				"error_tracker":  s.monitoring.GetErrorTracker() != nil,
				"log_aggregator": s.monitoring.GetLogAggregator() != nil,
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// systemStatsHandler provides system statistics and metrics
func (s *Server) systemStatsHandler(c *gin.Context) {
	ctx := c.Request.Context()

	// Start monitoring this request
	trace, ctx := s.monitoring.StartTrace(ctx, "system_stats")
	defer s.monitoring.FinishTrace(ctx, trace, nil)

	// Get system statistics
	stats := gin.H{
		"timestamp":   time.Now().Format(time.RFC3339),
		"uptime":      time.Since(time.Now().Add(-time.Hour)).String(), // Placeholder
		"version":     "1.0.0",
		"environment": s.config.Environment,
	}

	// Add monitoring statistics if available
	if s.monitoring.GetLogAggregator() != nil {
		end := time.Now()
		start := end.Add(-24 * time.Hour)
		logStats := s.monitoring.GetLogStatistics(start, end)
		stats["logs"] = logStats
	}

	c.JSON(http.StatusOK, stats)
}

// errorsHandler lists tracked errors
func (s *Server) errorsHandler(c *gin.Context) {
	ctx := c.Request.Context()

	// Parse query parameters
	category := c.Query("category")
	severity := c.Query("severity")
	resolved := c.Query("resolved")

	var resolvedPtr *bool
	if resolved != "" {
		r := resolved == "true"
		resolvedPtr = &r
	}

	var cat monitoring.ErrorCategory
	if category != "" {
		cat = monitoring.ErrorCategory(category)
	}

	var sev monitoring.ErrorSeverity
	if severity != "" {
		sev = monitoring.ErrorSeverity(severity)
	}

	errors := s.monitoring.GetErrors(cat, sev, resolvedPtr)

	s.monitoring.RecordHTTPEvent(ctx, "GET", "/monitoring/errors", 200, 0, 0, 0, c.Request.UserAgent(), c.ClientIP())

	c.JSON(http.StatusOK, gin.H{
		"errors":    errors,
		"count":     len(errors),
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// errorDetailsHandler gets details for a specific error
func (s *Server) errorDetailsHandler(c *gin.Context) {
	errorID := c.Param("id")

	if errorTracker := s.monitoring.GetErrorTracker(); errorTracker != nil {
		if errorEvent, exists := errorTracker.GetError(errorID); exists {
			c.JSON(http.StatusOK, errorEvent)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"error":    "Error not found",
		"error_id": errorID,
	})
}

// resolveErrorHandler marks an error as resolved
func (s *Server) resolveErrorHandler(c *gin.Context) {
	errorID := c.Param("id")

	var req struct {
		ResolvedBy string `json:"resolved_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	s.monitoring.ResolveError(errorID, req.ResolvedBy)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Error resolved successfully",
		"error_id":    errorID,
		"resolved_by": req.ResolvedBy,
		"timestamp":   time.Now().Format(time.RFC3339),
	})
}

// logsHandler retrieves log entries
func (s *Server) logsHandler(c *gin.Context) {
	// Parse query parameters for log filtering
	query := monitoring.LogSearchQuery{
		Level:     c.Query("level"),
		EventType: c.Query("event_type"),
		Component: c.Query("component"),
		Operation: c.Query("operation"),
		UserID:    c.Query("user_id"),
		RequestID: c.Query("request_id"),
		TraceID:   c.Query("trace_id"),
		Message:   c.Query("message"),
		Error:     c.Query("error"),
		Limit:     100, // Default limit
	}

	// Parse time range
	if startStr := c.Query("start"); startStr != "" {
		if start, err := time.Parse(time.RFC3339, startStr); err == nil {
			query.Start = start
		}
	}

	if endStr := c.Query("end"); endStr != "" {
		if end, err := time.Parse(time.RFC3339, endStr); err == nil {
			query.End = end
		}
	}

	logs := s.monitoring.SearchLogs(query)

	c.JSON(http.StatusOK, gin.H{
		"logs":      logs,
		"count":     len(logs),
		"query":     query,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// searchLogsHandler performs advanced log search
func (s *Server) searchLogsHandler(c *gin.Context) {
	var query monitoring.LogSearchQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid search query"})
		return
	}

	logs := s.monitoring.SearchLogs(query)

	c.JSON(http.StatusOK, gin.H{
		"logs":      logs,
		"count":     len(logs),
		"query":     query,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// logPatternsHandler retrieves detected log patterns
func (s *Server) logPatternsHandler(c *gin.Context) {
	eventType := c.Query("event_type")
	component := c.Query("component")

	patterns := s.monitoring.GetLogPatterns(eventType, component)

	c.JSON(http.StatusOK, gin.H{
		"patterns":  patterns,
		"count":     len(patterns),
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// logStatsHandler provides log statistics
func (s *Server) logStatsHandler(c *gin.Context) {
	// Parse time range
	end := time.Now()
	start := end.Add(-24 * time.Hour) // Default to last 24 hours

	if startStr := c.Query("start"); startStr != "" {
		if parsedStart, err := time.Parse(time.RFC3339, startStr); err == nil {
			start = parsedStart
		}
	}

	if endStr := c.Query("end"); endStr != "" {
		if parsedEnd, err := time.Parse(time.RFC3339, endStr); err == nil {
			end = parsedEnd
		}
	}

	stats := s.monitoring.GetLogStatistics(start, end)

	c.JSON(http.StatusOK, gin.H{
		"statistics": stats,
		"time_range": gin.H{
			"start": start.Format(time.RFC3339),
			"end":   end.Format(time.RFC3339),
		},
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// alertsHandler retrieves alerts
func (s *Server) alertsHandler(c *gin.Context) {
	resolved := c.Query("resolved")

	var resolvedPtr *bool
	if resolved != "" {
		r := resolved == "true"
		resolvedPtr = &r
	}

	alerts := s.monitoring.GetAlerts(resolvedPtr)

	c.JSON(http.StatusOK, gin.H{
		"alerts":    alerts,
		"count":     len(alerts),
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// createAlertRuleHandler creates a new alert rule
func (s *Server) createAlertRuleHandler(c *gin.Context) {
	// Implementation would depend on your alert rule structure
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Alert rule creation not implemented yet",
	})
}

// deleteAlertRuleHandler deletes an alert rule
func (s *Server) deleteAlertRuleHandler(c *gin.Context) {
	// Implementation would depend on your alert rule structure
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Alert rule deletion not implemented yet",
	})
}

// tracesHandler retrieves distributed traces
func (s *Server) tracesHandler(c *gin.Context) {
	// Implementation would depend on your tracing structure
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Trace listing not implemented yet",
	})
}

// traceDetailsHandler gets details for a specific trace
func (s *Server) traceDetailsHandler(c *gin.Context) {
	// Implementation would depend on your tracing structure
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "Trace details not implemented yet",
	})
}

// Helper methods for monitoring integration

// getUpdatedFields extracts the fields that were updated in a profile update request
func getUpdatedFields(req *interfaces.UpdateProfileRequest) []string {
	var fields []string
	if req.FirstName != nil {
		fields = append(fields, "first_name")
	}
	if req.LastName != nil {
		fields = append(fields, "last_name")
	}
	if req.Phone != nil {
		fields = append(fields, "phone")
	}
	return fields
}

// withMonitoring wraps a handler with comprehensive monitoring
func (s *Server) withMonitoring(operation string, handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.monitoring == nil {
			handler(c)
			return
		}

		ctx := c.Request.Context()
		start := time.Now()

		// Start trace
		trace, ctx := s.monitoring.StartTrace(ctx, operation)
		c.Request = c.Request.WithContext(ctx)

		// Add correlation context
		userID, _ := c.Get("user_id")
		requestID, _ := c.Get("request_id")

		correlation := s.monitoring.CreateCorrelation(
			fmt.Sprintf("%v", requestID),
			"", // session ID
			fmt.Sprintf("%v", userID),
			c.ClientIP(),
			c.Request.UserAgent(),
		)

		ctx = s.monitoring.WithCorrelation(ctx, correlation)
		c.Request = c.Request.WithContext(ctx)

		// Execute handler
		handler(c)

		// Record metrics and finish trace
		duration := time.Since(start)

		var err error
		if c.Writer.Status() >= 400 {
			err = fmt.Errorf("HTTP %d: %s", c.Writer.Status(), http.StatusText(c.Writer.Status()))
		}

		s.monitoring.FinishTrace(ctx, trace, err)

		// Record HTTP event
		s.monitoring.RecordHTTPEvent(
			ctx,
			c.Request.Method,
			c.FullPath(),
			c.Writer.Status(),
			duration,
			c.Request.ContentLength,
			int64(c.Writer.Size()),
			c.Request.UserAgent(),
			c.ClientIP(),
		)
	}
}

// trackAuthEvent records authentication-related events
func (s *Server) trackAuthEvent(ctx context.Context, method, userID string, success bool, duration time.Duration, details map[string]interface{}) {
	if s.monitoring != nil {
		s.monitoring.RecordAuthEvent(ctx, method, userID, success, duration, details)
	}
}

// trackUserEvent records user management events
func (s *Server) trackUserEvent(ctx context.Context, operation, userID string, details map[string]interface{}) {
	if s.monitoring != nil {
		s.monitoring.RecordUserEvent(ctx, operation, userID, details)
	}
}

// trackSecurityEvent records security-related events
func (s *Server) trackSecurityEvent(ctx context.Context, event, severity string, details map[string]interface{}) {
	if s.monitoring != nil {
		s.monitoring.RecordSecurityEvent(ctx, event, severity, details)
	}
}

// trackError records and tracks errors
func (s *Server) trackError(ctx context.Context, err error, category monitoring.ErrorCategory, operation, component string) string {
	if s.monitoring != nil {
		return s.monitoring.TrackError(ctx, err, category, operation, component)
	}
	return ""
}

func generateRequestID() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Int63())
}
