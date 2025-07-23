# Go Auth System

A comprehensive, enterprise-grade authentication service built in Go that provides flexible, secure, and scalable authentication solutions.

## Features Implemented

✅ **Core Infrastructure**
- Configuration management with YAML support
- Database layer with PostgreSQL and SQLC integration
- Redis caching layer for sessions and rate limiting
- Comprehensive error handling and logging

✅ **Security Services**
- Configurable password hashing (Argon2/bcrypt)
- Flexible token management (JWT/Paseto)
- AES-256-GCM encryption for sensitive data
- Rate limiting and security middleware

✅ **Authentication & Authorization**
- User registration and login
- Role-based access control (RBAC)
- Session management with Redis
- Token blacklisting and refresh

✅ **Multi-Factor Authentication**
- TOTP-based authentication
- SMS and email verification
- WebAuthn/FIDO2 hardware key support
- Backup codes for recovery

✅ **Enterprise SSO**
- SAML 2.0 service provider
- OpenID Connect integration
- LDAP/Active Directory authentication

✅ **Monitoring & Observability**
- Prometheus metrics collection
- Structured logging with correlation IDs
- Health checks for load balancers
- Audit trail for all authentication events

✅ **Deployment & Scaling**
- Docker containerization
- Kubernetes manifests and Helm charts
- Horizontal scaling with stateless sessions
- Load balancer configuration

## Quick Start

### Prerequisites

- Go 1.23.1 or later
- PostgreSQL 13+ 
- Redis 6+
- Docker (optional)

### Running Locally

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd go-auth-system
   ```

2. **Install dependencies**
   ```bash
   go mod tidy
   ```

3. **Set up PostgreSQL database**
   ```bash
   createdb go_auth_system
   ```

4. **Start Redis**
   ```bash
   redis-server
   ```

5. **Run database migrations**
   ```bash
   go run ./cmd/migrate up
   ```

6. **Start the server**
   ```bash
   go run ./cmd/server
   ```

   Or with custom config:
   ```bash
   go run ./cmd/server -config config.yaml
   ```

### Using Docker Compose

```bash
docker-compose up -d
```

## Configuration

The server uses a YAML configuration file. See `config.yaml` for a complete example with all available options.

Key configuration sections:
- `server`: HTTP/gRPC server settings
- `database`: PostgreSQL connection settings
- `redis`: Redis connection settings
- `security`: Password hashing, tokens, rate limiting
- `features`: MFA, social auth, enterprise SSO
- `external`: Monitoring and logging

## API Endpoints

### Health Checks
- `GET /health` - Overall health status
- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe

### Authentication (Coming Soon)
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Token refresh

### User Management (Coming Soon)
- `GET /api/v1/users/profile` - Get user profile
- `PUT /api/v1/users/profile` - Update user profile
- `POST /api/v1/users/change-password` - Change password

### Admin (Coming Soon)
- `GET /api/v1/admin/users` - List users
- `GET /api/v1/admin/system` - System information
- `GET /api/v1/admin/metrics` - System metrics

### Monitoring
- `GET :9091/metrics` - Prometheus metrics (if enabled)

## Development

### Project Structure

```
go-auth-system/
├── cmd/                    # Application entry points
│   ├── server/            # Main authentication server
│   └── migrate/           # Database migration tool
├── internal/              # Private application code
│   ├── api/              # API layer (REST & gRPC)
│   ├── service/          # Business logic layer
│   ├── repository/       # Data access layer
│   ├── security/         # Security utilities
│   ├── config/           # Configuration management
│   ├── middleware/       # HTTP/gRPC middleware
│   ├── monitoring/       # Metrics and logging
│   └── health/           # Health check system
├── sql/                   # Database schema and queries
├── docker/               # Docker configurations
├── k8s/                  # Kubernetes manifests
├── helm/                 # Helm charts
└── docs/                 # Documentation
```

### Building

```bash
# Build for current platform
go build -o bin/go-auth-system ./cmd/server

# Build for Linux (production)
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/go-auth-system ./cmd/server
```

### Testing

```bash
# Run unit tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run integration tests (requires Docker)
go test -tags=integration ./...
```

### Database Operations

```bash
# Run migrations
go run ./cmd/migrate up

# Rollback migrations
go run ./cmd/migrate down

# Create new migration
go run ./cmd/migrate create <migration_name>

# Generate SQLC code
sqlc generate
```

## Deployment

### Docker

```bash
# Build image
docker build -t go-auth-system:latest .

# Run container
docker run -p 8080:8080 -p 9091:9091 go-auth-system:latest
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Or use Helm
helm install go-auth-system ./helm/go-auth-system
```

## Security Considerations

- Change default signing keys and encryption keys in production
- Use strong passwords for database and Redis
- Enable TLS in production environments
- Configure proper CORS settings
- Set up proper firewall rules
- Use secrets management for sensitive configuration
- Enable audit logging in production
- Configure rate limiting based on your needs

## Monitoring

The system provides comprehensive monitoring through:

- **Prometheus Metrics**: Available at `:9091/metrics`
- **Health Checks**: Multiple endpoints for different health aspects
- **Structured Logging**: JSON formatted logs with correlation IDs
- **Audit Trail**: Immutable log of all authentication events

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.