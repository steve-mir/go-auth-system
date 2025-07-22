# REST API Server

This package implements a comprehensive REST API server for the go-auth-system authentication backend. It provides HTTP/JSON endpoints for all authentication and user management operations.

## Features

- **Multi-Protocol Support**: REST API with JSON request/response format
- **Comprehensive Authentication**: Registration, login, logout, token refresh, and validation
- **User Management**: Profile management, password changes, and user administration
- **Role-Based Access Control**: Role and permission management with RBAC support
- **Admin Dashboard**: Administrative endpoints for system management
- **Security Middleware**: Authentication, authorization, rate limiting, and input validation
- **Error Handling**: Structured error responses with proper HTTP status codes
- **Request Validation**: Comprehensive input validation and sanitization
- **Pagination Support**: Paginated responses for list endpoints
- **Health Checks**: Health, liveness, and readiness endpoints

## Architecture

The REST API server follows a layered architecture:

```
┌─────────────────────────────────────────┐
│              HTTP Clients               │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│            Gin HTTP Router              │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│             Middleware Stack            │
│  • Recovery                             │
│  • Request ID                           │
│  • Logging                              │
│  • CORS                                 │
│  • Health Check                         │
│  • Metrics                              │
│  • Security (Rate Limiting)             │
│  • Authentication (Protected Routes)    │
│  • Authorization (Admin Routes)         │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│              Route Handlers             │
│  • Auth Routes                          │
│  • User Routes                          │
│  • Role Routes                          │
│  • Admin Routes                         │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│             Service Layer               │
│  • AuthService                          │
│  • UserService                          │
│  • RoleService                          │
└─────────────────────────────────────────┘
```

## API Endpoints

### Authentication Endpoints (Public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register a new user |
| POST | `/api/v1/auth/login` | Authenticate user and get tokens |
| POST | `/api/v1/auth/logout` | Logout and invalidate tokens |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/validate` | Validate token |

### User Management Endpoints (Protected)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/users/profile` | Get current user profile | User |
| PUT | `/api/v1/users/profile` | Update current user profile | User |
| POST | `/api/v1/users/change-password` | Change user password | User |
| DELETE | `/api/v1/users/account` | Delete user account | User |
| GET | `/api/v1/users/roles` | Get user roles | User |
| GET | `/api/v1/users` | List all users | Admin |
| GET | `/api/v1/users/:user_id` | Get user by ID | Admin |
| PUT | `/api/v1/users/:user_id` | Update user by ID | Admin |
| DELETE | `/api/v1/users/:user_id` | Delete user by ID | Admin |

### Role Management Endpoints (Admin Only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/roles` | Create new role |
| GET | `/api/v1/roles` | List all roles |
| GET | `/api/v1/roles/:role_id` | Get role by ID |
| PUT | `/api/v1/roles/:role_id` | Update role |
| DELETE | `/api/v1/roles/:role_id` | Delete role |
| POST | `/api/v1/roles/:role_id/users/:user_id` | Assign role to user |
| DELETE | `/api/v1/roles/:role_id/users/:user_id` | Remove role from user |
| GET | `/api/v1/roles/:role_id/users` | Get users with role |
| POST | `/api/v1/roles/validate-permission` | Validate user permission |
| POST | `/api/v1/roles/validate-access` | Validate access with ABAC |

### Admin Dashboard Endpoints (Admin Only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/system/info` | Get system information |
| GET | `/api/v1/admin/system/health` | Get detailed system health |
| GET | `/api/v1/admin/system/metrics` | Get system metrics |
| GET | `/api/v1/admin/users/stats` | Get user statistics |
| POST | `/api/v1/admin/users/bulk-actions` | Perform bulk user actions |
| GET | `/api/v1/admin/users/sessions` | Get all user sessions |
| DELETE | `/api/v1/admin/users/sessions/:session_id` | Delete user session |
| GET | `/api/v1/admin/roles/stats` | Get role statistics |
| POST | `/api/v1/admin/roles/bulk-assign` | Bulk role assignment |
| GET | `/api/v1/admin/audit/logs` | Get audit logs |
| GET | `/api/v1/admin/audit/events` | Get audit events |
| GET | `/api/v1/admin/config` | Get system configuration |
| PUT | `/api/v1/admin/config` | Update system configuration |
| POST | `/api/v1/admin/config/reload` | Reload system configuration |

### Health Check Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Root endpoint with service info |
| GET | `/health` | Basic health check |
| GET | `/health/live` | Liveness probe |
| GET | `/health/ready` | Readiness probe |

## Request/Response Format

### Standard Response Format

```json
{
  "success": true,
  "data": { ... },
  "request_id": "req-123",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": { ... }
  },
  "request_id": "req-123",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Paginated Response Format

```json
{
  "success": true,
  "data": [ ... ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 100,
    "total_pages": 10,
    "has_next": true,
    "has_prev": false
  },
  "request_id": "req-123",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Authentication

Protected endpoints require a valid JWT token in the Authorization header:

```
Authorization: Bearer <access_token>
```

Admin endpoints additionally require the user to have admin role.

## Input Validation

All endpoints perform comprehensive input validation:

- **JSON Schema Validation**: Request body structure validation
- **Field Validation**: Email format, password strength, UUID format, etc.
- **Input Sanitization**: HTML tag removal and whitespace trimming
- **Parameter Validation**: URL parameters and query parameters

### Validation Error Response

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": {
      "validation_errors": [
        {
          "field": "email",
          "message": "Must be a valid email address",
          "value": "invalid-email"
        }
      ]
    }
  }
}
```

## Pagination

List endpoints support pagination with query parameters:

- `page`: Page number (default: 1)
- `limit`: Items per page (default: 10, max: 100)
- `sort_by`: Sort field (varies by endpoint)
- `sort_order`: Sort direction (`asc` or `desc`, default: `asc`)
- `search`: Search term (where applicable)

Example: `/api/v1/users?page=2&limit=20&sort_by=created_at&sort_order=desc`

## Error Codes

### Authentication Errors
- `AUTH_INVALID_CREDENTIALS`: Invalid email/username or password
- `AUTH_USER_NOT_FOUND`: User not found
- `AUTH_ACCOUNT_LOCKED`: Account locked due to failed attempts
- `AUTH_INVALID_TOKEN`: Invalid or malformed token
- `AUTH_TOKEN_EXPIRED`: Token has expired

### Authorization Errors
- `UNAUTHORIZED`: Missing or invalid authorization header
- `FORBIDDEN`: Insufficient permissions
- `INSUFFICIENT_PERMISSIONS`: Required role not found

### Validation Errors
- `VALIDATION_ERROR`: Request validation failed
- `BAD_REQUEST`: Invalid request format
- `INVALID_UUID`: Invalid UUID format

### General Errors
- `NOT_FOUND`: Resource not found
- `CONFLICT`: Resource already exists
- `TOO_MANY_REQUESTS`: Rate limit exceeded
- `INTERNAL_ERROR`: Internal server error

## Security Features

### Middleware Security
- **Rate Limiting**: Sliding window rate limiting per IP and user
- **CORS**: Configurable cross-origin request handling
- **Request ID**: Unique request tracking for debugging
- **Input Sanitization**: HTML tag removal and XSS prevention

### Authentication Security
- **Token Validation**: JWT/Paseto token verification
- **Token Blacklisting**: Revoked token checking
- **Session Management**: Secure session handling
- **Account Lockout**: Progressive delays for failed attempts

### Authorization Security
- **Role-Based Access Control**: Hierarchical role system
- **Permission Validation**: Fine-grained permission checking
- **Admin Protection**: Admin-only endpoint protection
- **Context Isolation**: User context isolation per request

## Usage Example

```go
package main

import (
    "context"
    "time"
    
    "github.com/steve-mir/go-auth-system/internal/api/rest"
    "github.com/steve-mir/go-auth-system/internal/config"
    "github.com/steve-mir/go-auth-system/internal/middleware"
)

func main() {
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
    middlewareManager := middleware.NewMiddlewareManager(
        middleware.DefaultConfig(), 
        nil, // Redis client
    )

    // Create services (implement these based on your needs)
    var authService auth.AuthService
    var userService user.UserService
    var roleService role.Service

    // Create and start server
    server := rest.NewServer(
        cfg,
        middlewareManager,
        authService,
        userService,
        roleService,
    )

    ctx := context.Background()
    if err := server.Start(ctx); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}
```

## Testing

The package includes comprehensive integration tests covering:

- Health check endpoints
- Authentication flows
- Input validation
- Error handling
- Middleware functionality
- Pagination
- Authorization checks

Run tests with:
```bash
go test ./internal/api/rest -v
```

## Dependencies

- **Gin**: HTTP web framework
- **Validator**: Request validation
- **UUID**: UUID generation and validation
- **Testify**: Testing framework
- **Internal Services**: Auth, User, and Role services
- **Internal Middleware**: Security and rate limiting middleware