package rest

import (
	"context"
	"log"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/health"
	"github.com/steve-mir/go-auth-system/internal/middleware"
	"github.com/steve-mir/go-auth-system/internal/service/admin"
	"github.com/steve-mir/go-auth-system/internal/service/auth"
	"github.com/steve-mir/go-auth-system/internal/service/role"
	"github.com/steve-mir/go-auth-system/internal/service/user"
)

// ExampleUsage demonstrates how to set up and use the REST API server
func ExampleUsage() {
	// Create server configuration
	cfg := &config.ServerConfig{
		Host:         "localhost",
		Port:         8080,
		Environment:  "development",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Create middleware manager
	middlewareConfig := middleware.DefaultConfig()
	middlewareManager := middleware.NewMiddlewareManager(middlewareConfig, nil)

	// Create service instances (these would be properly initialized in real usage)
	var authService auth.AuthService
	var userService user.UserService
	var roleService role.Service
	var adminService admin.AdminService
	healthService := health.NewService()

	// Create REST API server
	server := NewServer(
		cfg,
		middlewareManager,
		authService,
		userService,
		roleService,
		adminService,
		healthService,
	)

	// Start the server
	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		log.Fatalf("Failed to start REST API server: %v", err)
	}
}

// ExampleAPIEndpoints shows the available API endpoints
func ExampleAPIEndpoints() {
	endpoints := map[string][]string{
		"Authentication (Public)": {
			"POST /api/v1/auth/register",
			"POST /api/v1/auth/login",
			"POST /api/v1/auth/logout",
			"POST /api/v1/auth/refresh",
			"POST /api/v1/auth/validate",
		},
		"User Management (Protected)": {
			"GET /api/v1/users/profile",
			"PUT /api/v1/users/profile",
			"POST /api/v1/users/change-password",
			"DELETE /api/v1/users/account",
			"GET /api/v1/users/roles",
		},
		"User Management (Admin Only)": {
			"GET /api/v1/users",
			"GET /api/v1/users/:user_id",
			"PUT /api/v1/users/:user_id",
			"DELETE /api/v1/users/:user_id",
		},
		"Role Management (Admin Only)": {
			"POST /api/v1/roles",
			"GET /api/v1/roles",
			"GET /api/v1/roles/:role_id",
			"PUT /api/v1/roles/:role_id",
			"DELETE /api/v1/roles/:role_id",
			"POST /api/v1/roles/:role_id/users/:user_id",
			"DELETE /api/v1/roles/:role_id/users/:user_id",
			"GET /api/v1/roles/:role_id/users",
			"POST /api/v1/roles/validate-permission",
			"POST /api/v1/roles/validate-access",
		},
		"Admin Dashboard (Admin Only)": {
			"GET /api/v1/admin/system/info",
			"GET /api/v1/admin/system/health",
			"GET /api/v1/admin/system/metrics",
			"GET /api/v1/admin/users/stats",
			"POST /api/v1/admin/users/bulk-actions",
			"GET /api/v1/admin/users/sessions",
			"DELETE /api/v1/admin/users/sessions/:session_id",
			"GET /api/v1/admin/roles/stats",
			"POST /api/v1/admin/roles/bulk-assign",
			"GET /api/v1/admin/audit/logs",
			"GET /api/v1/admin/audit/events",
			"GET /api/v1/admin/config",
			"PUT /api/v1/admin/config",
			"POST /api/v1/admin/config/reload",
		},
		"Health Checks": {
			"GET /health",
			"GET /health/live",
			"GET /health/ready",
		},
	}

	log.Println("Available API Endpoints:")
	for category, endpointList := range endpoints {
		log.Printf("\n%s:", category)
		for _, endpoint := range endpointList {
			log.Printf("  %s", endpoint)
		}
	}
}

// ExampleRequestResponse shows example request and response formats
func ExampleRequestResponse() {
	examples := map[string]interface{}{
		"Register Request": map[string]interface{}{
			"email":      "user@example.com",
			"username":   "johndoe",
			"password":   "securepassword123",
			"first_name": "John",
			"last_name":  "Doe",
			"phone":      "+1234567890",
		},
		"Register Response": map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"user_id":    "123e4567-e89b-12d3-a456-426614174000",
				"email":      "user@example.com",
				"username":   "johndoe",
				"created_at": "2024-01-01T00:00:00Z",
				"message":    "User registered successfully",
			},
			"request_id": "req-123",
			"timestamp":  "2024-01-01T00:00:00Z",
		},
		"Login Request": map[string]interface{}{
			"email":    "user@example.com",
			"password": "securepassword123",
		},
		"Login Response": map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"user_id":       "123e4567-e89b-12d3-a456-426614174000",
				"email":         "user@example.com",
				"username":      "johndoe",
				"access_token":  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
				"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"expires_at":    "2024-01-01T01:00:00Z",
			},
			"request_id": "req-124",
			"timestamp":  "2024-01-01T00:00:00Z",
		},
		"Error Response": map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "AUTH_INVALID_CREDENTIALS",
				"message": "Invalid email/username or password",
				"details": nil,
			},
			"request_id": "req-125",
			"timestamp":  "2024-01-01T00:00:00Z",
		},
		"Validation Error Response": map[string]interface{}{
			"success": false,
			"error": map[string]interface{}{
				"code":    "VALIDATION_ERROR",
				"message": "Request validation failed",
				"details": map[string]interface{}{
					"validation_errors": []map[string]interface{}{
						{
							"field":   "email",
							"message": "Must be a valid email address",
							"value":   "invalid-email",
						},
						{
							"field":   "password",
							"message": "Must be at least 8 characters long",
							"value":   "123",
						},
					},
				},
			},
			"request_id": "req-126",
			"timestamp":  "2024-01-01T00:00:00Z",
		},
		"Paginated Response": map[string]interface{}{
			"success": true,
			"data": []map[string]interface{}{
				{
					"id":       "123e4567-e89b-12d3-a456-426614174000",
					"email":    "user1@example.com",
					"username": "user1",
				},
				{
					"id":       "123e4567-e89b-12d3-a456-426614174001",
					"email":    "user2@example.com",
					"username": "user2",
				},
			},
			"pagination": map[string]interface{}{
				"page":        1,
				"limit":       10,
				"total":       100,
				"total_pages": 10,
				"has_next":    true,
				"has_prev":    false,
			},
			"request_id": "req-127",
			"timestamp":  "2024-01-01T00:00:00Z",
		},
	}

	log.Println("Example Request/Response Formats:")
	for name, example := range examples {
		log.Printf("\n%s:", name)
		log.Printf("%+v", example)
	}
}

// ExampleMiddlewareUsage shows how middleware is applied
func ExampleMiddlewareUsage() {
	middlewareOrder := []string{
		"1. Recovery Middleware - Handles panics and returns 500 errors",
		"2. Request ID Middleware - Adds unique request ID to each request",
		"3. Logging Middleware - Logs request details",
		"4. CORS Middleware - Handles cross-origin requests",
		"5. Health Check Middleware - Early exit for health endpoints",
		"6. Metrics Middleware - Collects request metrics",
		"7. Security Middleware - Rate limiting and security headers",
		"8. Authentication Middleware - Validates JWT tokens (protected routes only)",
		"9. Authorization Middleware - Checks user roles and permissions (admin routes only)",
	}

	log.Println("Middleware Application Order:")
	for _, middleware := range middlewareOrder {
		log.Printf("  %s", middleware)
	}
}

// ExampleSecurityFeatures shows the security features implemented
func ExampleSecurityFeatures() {
	features := map[string][]string{
		"Authentication": {
			"JWT/Paseto token validation",
			"Bearer token format enforcement",
			"Token expiration checking",
			"Token blacklisting support",
		},
		"Authorization": {
			"Role-based access control (RBAC)",
			"Admin-only route protection",
			"User context extraction",
			"Permission validation",
		},
		"Input Validation": {
			"JSON schema validation",
			"Field-level validation rules",
			"Input sanitization",
			"UUID format validation",
		},
		"Rate Limiting": {
			"Sliding window rate limiting",
			"IP-based and user-based limits",
			"Account lockout policies",
			"Suspicious activity detection",
		},
		"Security Headers": {
			"CORS configuration",
			"Request ID tracking",
			"Error response sanitization",
			"Secure error handling",
		},
	}

	log.Println("Security Features:")
	for category, featureList := range features {
		log.Printf("\n%s:", category)
		for _, feature := range featureList {
			log.Printf("  - %s", feature)
		}
	}
}
