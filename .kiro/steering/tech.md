# Technology Stack & Build System

## Core Technologies

### Language & Runtime
- **Go 1.23.1**: Primary development language
- **Module**: `github.com/steve-mir/go-auth-system-system`

### Database & Storage
- **PostgreSQL**: Primary database for user data, roles, and audit logs
- **Redis**: Caching layer for sessions, rate limiting, and token blacklisting
- **SQLC**: Type-safe SQL query generation and database operations

### Security & Authentication
- **JWT/Paseto**: Configurable token formats for authentication
- **Argon2/bcrypt**: Configurable password hashing algorithms
- **AES-256-GCM**: Encryption for sensitive PII data
- **TLS 1.3**: Transport layer security

### API & Communication
- **REST API**: HTTP/JSON endpoints with OpenAPI documentation
- **gRPC**: Protocol buffer-based RPC communication
- **Protocol Buffers**: Service definitions and message serialization

### External Integrations
- **OAuth 2.0**: Social authentication (Google, Facebook, GitHub)
- **SAML 2.0**: Enterprise SSO integration
- **OpenID Connect**: Modern SSO protocol support
- **LDAP/Active Directory**: Directory service authentication
- **WebAuthn/FIDO2**: Hardware key authentication

### Monitoring & Observability
- **Prometheus**: Metrics collection and monitoring
- **Structured Logging**: JSON-formatted application logs
- **Health Checks**: Load balancer and orchestration integration
- **Audit Trails**: Immutable authentication event logging

## Build System & Commands

### Development Setup
```bash
# Initialize and download dependencies
go mod tidy

# Generate SQLC database code
sqlc generate

# Generate Protocol Buffer code
protoc --go_out=. --go-grpc_out=. proto/*.proto

# Generate mocks for testing
go generate ./...
```

### Testing
```bash
# Run unit tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run integration tests (requires Docker)
go test -tags=integration ./...

# Run end-to-end tests
go test -tags=e2e ./...
```

### Building & Running
```bash
# Build the application
go build -o bin/go-auth-system ./cmd/server

# Run in development mode
go run ./cmd/server

# Build for production
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/go-auth-system ./cmd/server
```

### Database Operations
```bash
# Run database migrations
go run ./cmd/migrate up

# Rollback migrations
go run ./cmd/migrate down

# Create new migration
go run ./cmd/migrate create <migration_name>
```

### Docker & Deployment
```bash
# Build Docker image
docker build -t go-auth-system:latest .

# Run with Docker Compose (development)
docker-compose up -d

# Deploy to Kubernetes
kubectl apply -f k8s/

# Deploy with Helm
helm install go-auth-system ./helm/go-auth-system
```

## Code Generation Tools

- **SQLC**: Database query generation from SQL files
- **Protocol Buffers**: gRPC service and message generation
- **Mockgen**: Mock generation for testing interfaces
- **Swagger/OpenAPI**: REST API documentation generation

## Configuration Management

- **YAML Configuration**: Environment-specific settings
- **Environment Variables**: Runtime configuration overrides
- **Feature Flags**: Configurable feature enablement
- **Hot Reloading**: Configuration updates without restart