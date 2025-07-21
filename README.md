# Go Auth System

A comprehensive, enterprise-grade authentication service built in Go that provides flexible, secure, and scalable authentication solutions. The system is designed to be adaptable for various applications from social media to banking, similar to FusionAuth or Firebase Authentication.

## Features

- **Multi-Protocol Support**: Both REST and gRPC APIs for maximum integration flexibility
- **Configurable Security**: Choice between JWT/Paseto tokens and Argon2/bcrypt password hashing
- **Enterprise SSO**: SAML 2.0, OpenID Connect, and LDAP/Active Directory integration
- **Multi-Factor Authentication**: TOTP, SMS, email, and WebAuthn/FIDO2 support
- **Social Authentication**: Google, Facebook, and GitHub OAuth integration
- **Role-Based Access Control**: Comprehensive RBAC with flexible permission management
- **Admin Dashboard**: Web-based administration interface for user and system management
- **Deployment Flexibility**: Supports both monolithic and microservice architectures

## Quick Start

### Prerequisites

- Go 1.23.1 or later
- PostgreSQL 12+ 
- Redis 6+
- Docker (optional, for containerized dependencies)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/steve-mir/go-auth-system.git
cd go-auth-system
```

2. Install dependencies:
```bash
go mod tidy
```

3. Set up the database:
```bash
# Using Docker
make postgres
make createdb

# Or use your existing PostgreSQL instance
createdb auth_system
```

4. Set up Redis:
```bash
# Using Docker
make redis

# Or use your existing Redis instance
```

5. Configure the application:
```bash
# Copy the example configuration
cp config.example.yaml config.yaml

# Or use environment variables (see app.env for examples)
cp app.env .env
```

6. Run the application:
```bash
# Using configuration file
make run-config

# Or using environment variables
source .env && make run
```

## Configuration

The application supports configuration through both YAML files and environment variables. Environment variables take precedence over file configuration.

### Configuration File

Copy `config.example.yaml` to `config.yaml` and modify as needed:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 9090

database:
  host: "localhost"
  port: 5432
  name: "auth_system"
  user: "postgres"
  password: "postgres"

security:
  password_hash:
    algorithm: "argon2"  # "argon2" or "bcrypt"
  token:
    type: "jwt"          # "jwt" or "paseto"
    access_ttl: "15m"
    refresh_ttl: "168h"
```

### Environment Variables

Key environment variables (see `app.env` for complete list):

- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` - Database connection
- `REDIS_HOST`, `REDIS_PORT` - Redis connection
- `JWT_SIGNING_KEY` - JWT signing key (required)
- `ENCRYPTION_MASTER_KEY` - Master encryption key for PII data
- `PASSWORD_HASH_ALGORITHM` - Password hashing algorithm (`argon2` or `bcrypt`)
- `TOKEN_TYPE` - Token type (`jwt` or `paseto`)

## API Documentation

### REST API

The REST API is available at `http://localhost:8080/api/v1/` with the following endpoints:

- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/refresh` - Token refresh
- `GET /users/profile` - Get user profile
- `PUT /users/profile` - Update user profile

### gRPC API

The gRPC API is available at `localhost:9090`. Protocol buffer definitions are in the `proto/` directory.

## Development

### Building

```bash
# Build the application
make build

# Run tests
make test

# Clean build artifacts
make clean
```

### Database Operations

```bash
# Create database migration
make migrate_init

# Run migrations
make migrateup

# Rollback migrations
make migratedown

# Generate SQLC code
make sqlc
```

### Protocol Buffers

```bash
# Generate gRPC code from proto files
make proto
```

## Deployment

### Docker

```bash
# Build Docker image
docker build -t go-auth-system:latest .

# Run with Docker Compose
docker-compose up -d
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Or use Helm
helm install go-auth-system ./helm/go-auth-system
```

## Security Considerations

- Always use strong, unique keys for JWT signing and encryption
- Enable TLS in production environments
- Use environment variables or secure key management for sensitive configuration
- Regularly rotate encryption keys
- Monitor authentication events and failed login attempts
- Configure appropriate rate limiting for your use case

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- Create an issue on GitHub
- Check the documentation in the `docs/` directory
- Review the example configuration files

## Architecture

The system follows a layered architecture:

- **API Layer**: REST and gRPC handlers
- **Service Layer**: Business logic implementation
- **Repository Layer**: Data access with SQLC
- **Infrastructure Layer**: Cross-cutting concerns (caching, logging, metrics)

For detailed architecture documentation, see the design document in `.kiro/specs/auth-backend-system/design.md`.