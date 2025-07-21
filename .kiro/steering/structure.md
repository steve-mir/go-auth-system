# Project Structure & Organization

## Directory Layout

```
go-auth-system/
├── cmd/                    # Application entry points
│   ├── server/            # Main authentication server
│   └── migrate/           # Database migration tool
├── internal/              # Private application code
│   ├── api/              # API layer (REST & gRPC)
│   │   ├── rest/         # REST API handlers and middleware
│   │   └── grpc/         # gRPC service implementations
│   ├── service/          # Business logic layer
│   │   ├── auth/         # Authentication service
│   │   ├── user/         # User management service
│   │   ├── role/         # Role and permission service
│   │   ├── mfa/          # Multi-factor authentication
│   │   └── sso/          # Single sign-on integrations
│   ├── repository/       # Data access layer
│   │   ├── postgres/     # PostgreSQL implementations
│   │   └── redis/        # Redis cache implementations
│   ├── security/         # Security utilities
│   │   ├── hash/         # Password hashing (Argon2/bcrypt)
│   │   ├── token/        # Token management (JWT/Paseto)
│   │   ├── crypto/       # Encryption utilities
│   │   └── rate/         # Rate limiting
│   ├── config/           # Configuration management
│   ├── middleware/       # HTTP/gRPC middleware
│   └── util/             # Shared utilities
├── pkg/                   # Public library code
│   ├── client/           # Client SDKs
│   └── types/            # Shared types and interfaces
├── proto/                 # Protocol buffer definitions
├── sql/                   # Database schema and queries
│   ├── migrations/       # Database migration files
│   └── queries/          # SQLC query definitions
├── web/                   # Admin dashboard frontend
├── docker/                # Docker configurations
├── k8s/                   # Kubernetes manifests
├── helm/                  # Helm charts
├── docs/                  # Documentation
└── scripts/               # Build and deployment scripts
```

## Architecture Patterns

### Layered Architecture
- **API Layer**: Protocol-specific handlers (REST/gRPC)
- **Service Layer**: Business logic and orchestration
- **Repository Layer**: Data access abstraction
- **Infrastructure Layer**: Cross-cutting concerns

### Service Organization
- Each service has a clear interface and implementation
- Services are organized by domain (auth, user, role, etc.)
- Dependency injection for service composition
- Interface-based design for testability

### Configuration Structure
```
config/
├── config.go             # Configuration types and loading
├── defaults.go           # Default configuration values
└── validation.go         # Configuration validation
```

### Database Layer Organization
```
sql/
├── migrations/           # Versioned schema changes
│   ├── 001_initial.up.sql
│   └── 001_initial.down.sql
├── queries/              # SQLC query definitions
│   ├── users.sql
│   ├── roles.sql
│   └── sessions.sql
└── sqlc.yaml            # SQLC configuration
```

## Naming Conventions

### Go Code Standards
- **Packages**: Short, lowercase, single words when possible
- **Interfaces**: Descriptive names ending with common suffixes (Service, Repository, Handler)
- **Structs**: PascalCase with descriptive names
- **Functions**: PascalCase for exported, camelCase for private
- **Constants**: PascalCase or SCREAMING_SNAKE_CASE for package-level

### Database Conventions
- **Tables**: Plural, snake_case (users, user_roles, audit_logs)
- **Columns**: snake_case with descriptive names
- **Primary Keys**: Always `id` of type UUID
- **Foreign Keys**: `{table}_id` format
- **Timestamps**: `created_at`, `updated_at`, `deleted_at`

### API Conventions
- **REST Endpoints**: RESTful resource naming (/api/v1/users/{id})
- **gRPC Services**: PascalCase service names (AuthService, UserService)
- **gRPC Methods**: PascalCase method names (Login, GetProfile)
- **Request/Response**: Descriptive message names (LoginRequest, LoginResponse)

## File Organization Principles

### Service Structure
```
service/auth/
├── service.go            # Service interface and implementation
├── models.go             # Domain models and DTOs
├── errors.go             # Service-specific errors
└── service_test.go       # Unit tests
```

### Repository Structure
```
repository/postgres/
├── user.go               # User repository implementation
├── role.go               # Role repository implementation
├── queries.sql.go        # SQLC generated code
└── migrations.go         # Migration utilities
```

### Testing Organization
- Unit tests alongside source files (`*_test.go`)
- Integration tests in separate `integration/` directory
- Test utilities and fixtures in `testutil/` package
- Mock implementations in `mocks/` directory

## Import Organization

### Standard Import Order
1. Standard library imports
2. Third-party library imports
3. Internal application imports

### Example Import Structure
```go
import (
    // Standard library
    "context"
    "fmt"
    "time"
    
    // Third-party
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
    
    // Internal
    "github.com/steve-mir/go-auth-system/internal/config"
    "github.com/steve-mir/go-auth-system/internal/service/auth"
)
```

## Error Handling Patterns

- Centralized error types in `internal/errors/`
- Service-specific error wrapping
- Consistent error response formats across protocols
- Proper error logging with context and trace IDs