# Token Management System

This package provides a flexible token management system that supports both JWT and Paseto tokens through a unified interface.

## Features

- **Multi-format Support**: JWT and Paseto token formats
- **Configuration-driven**: Choose token type and parameters via configuration
- **Token Lifecycle**: Generate, validate, refresh, and revoke tokens
- **Security**: Built-in token blacklisting and expiration handling
- **Extensible**: Easy to add new token formats

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "time"
    
    "github.com/steve-mir/go-auth-system/internal/config"
    "github.com/steve-mir/go-auth-system/internal/security/token"
)

func main() {
    // Create configuration
    cfg := &config.TokenConfig{
        Type:       "jwt",
        SigningKey: "your-secret-key",
        AccessTTL:  time.Minute * 15,
        RefreshTTL: time.Hour * 24 * 7,
        Issuer:     "my-app",
        Audience:   "my-users",
    }

    // Create token service
    factory := token.NewFactory(cfg)
    service, err := factory.CreateTokenService()
    if err != nil {
        panic(err)
    }

    // Generate tokens
    ctx := context.Background()
    claims := token.TokenClaims{
        Email:    "user@example.com",
        Username: "johndoe",
        Roles:    []string{"user"},
    }

    tokenPair, err := service.GenerateTokens(ctx, "user-123", claims)
    if err != nil {
        panic(err)
    }

    // Validate token
    validatedClaims, err := service.ValidateToken(ctx, tokenPair.AccessToken)
    if err != nil {
        panic(err)
    }

    // Use validated claims...
}
```

### Configuration Builder

```go
config := token.NewConfigBuilder().
    WithType("paseto").
    WithAccessTTL(time.Minute * 30).
    WithRefreshTTL(time.Hour * 48).
    WithEncryptionKey("your-32-character-encryption-key").
    WithIssuer("my-application").
    WithAudience("my-users").
    Build()
```

## Supported Token Types

### JWT (JSON Web Tokens)

- **Type**: `"jwt"`
- **Required Config**: `SigningKey`
- **Features**: Industry standard, widely supported, stateless
- **Use Case**: General purpose authentication

```go
config := &config.TokenConfig{
    Type:       "jwt",
    SigningKey: "your-secret-signing-key",
    AccessTTL:  time.Minute * 15,
    RefreshTTL: time.Hour * 24,
    Issuer:     "my-app",
    Audience:   "my-users",
}
```

### Paseto (Platform-Agnostic Security Tokens)

- **Type**: `"paseto"`
- **Required Config**: `EncryptionKey` (32+ characters)
- **Features**: Encrypted by default, misuse-resistant, version-aware
- **Use Case**: High-security applications

```go
config := &config.TokenConfig{
    Type:          "paseto",
    EncryptionKey: "your-32-character-encryption-key",
    AccessTTL:     time.Minute * 15,
    RefreshTTL:    time.Hour * 24,
    Issuer:        "my-app",
    Audience:      "my-users",
}
```

## Token Claims

The `TokenClaims` struct contains all the information stored in a token:

```go
type TokenClaims struct {
    UserID    string            // User identifier
    Email     string            // User email
    Username  string            // Username (optional)
    Roles     []string          // User roles
    TokenType TokenType         // "access" or "refresh"
    IssuedAt  time.Time         // Token issue time
    ExpiresAt time.Time         // Token expiration time
    Issuer    string            // Token issuer
    Audience  string            // Token audience
    Subject   string            // Token subject (usually user ID)
    JTI       string            // JWT ID for tracking
    Metadata  map[string]string // Additional metadata
}
```

## Token Operations

### Generate Token Pair

```go
claims := token.TokenClaims{
    Email:    "user@example.com",
    Username: "johndoe",
    Roles:    []string{"user", "admin"},
    Metadata: map[string]string{
        "department": "engineering",
    },
}

tokenPair, err := service.GenerateTokens(ctx, "user-123", claims)
```

### Validate Token

```go
claims, err := service.ValidateToken(ctx, tokenString)
if err != nil {
    // Handle validation error
    switch err.(type) {
    case *token.TokenError:
        tokenErr := err.(*token.TokenError)
        switch tokenErr.Type {
        case token.ErrorTypeExpired:
            // Token expired
        case token.ErrorTypeRevoked:
            // Token revoked
        case token.ErrorTypeSignature:
            // Invalid signature
        }
    }
}
```

### Refresh Tokens

```go
newTokenPair, err := service.RefreshToken(ctx, refreshToken)
```

### Revoke Token

```go
err := service.RevokeToken(ctx, tokenString)
```

## Error Handling

The package provides detailed error types for different failure scenarios:

- `ErrorTypeValidation`: General validation errors
- `ErrorTypeExpired`: Token has expired
- `ErrorTypeRevoked`: Token has been revoked
- `ErrorTypeSignature`: Invalid token signature
- `ErrorTypeFormat`: Invalid token format
- `ErrorTypeGeneration`: Token generation failed
- `ErrorTypeNotFound`: Token not found
- `ErrorTypeInvalidKey`: Invalid signing/encryption key
- `ErrorTypeInvalidType`: Invalid token type
- `ErrorTypeInvalidClaim`: Invalid token claim

## Security Considerations

### Token Storage

- Store tokens securely (e.g., HTTP-only cookies for web apps)
- Never log tokens in plain text
- Use HTTPS for token transmission

### Key Management

- Use strong, randomly generated keys
- Rotate keys regularly
- Store keys securely (environment variables, key management systems)

### Token Expiration

- Use short-lived access tokens (15-30 minutes)
- Use longer-lived refresh tokens (days to weeks)
- Implement proper token refresh flows

### Token Revocation

- Implement token blacklisting for immediate revocation
- Use Redis or similar for distributed blacklist storage
- Clean up expired blacklist entries

## Production Considerations

### Dependencies

This implementation includes simplified JWT and Paseto implementations for demonstration. For production use, consider using proper libraries:

- JWT: `github.com/golang-jwt/jwt/v5`
- Paseto: `github.com/o1egl/paseto`

### Redis Integration

The current implementation uses in-memory blacklists. For production:

```go
// TODO: Implement Redis-based blacklist
type RedisBlacklist struct {
    client *redis.Client
}

func (r *RedisBlacklist) AddToken(tokenID string, expiresAt time.Time) error {
    ttl := time.Until(expiresAt)
    return r.client.Set(ctx, "blacklist:"+tokenID, "1", ttl).Err()
}

func (r *RedisBlacklist) IsBlacklisted(tokenID string) (bool, error) {
    result := r.client.Get(ctx, "blacklist:"+tokenID)
    if result.Err() == redis.Nil {
        return false, nil
    }
    return result.Err() == nil, result.Err()
}
```

### Monitoring

Add metrics for:
- Token generation rate
- Token validation success/failure rate
- Token expiration events
- Blacklist size and operations

### Testing

The package includes comprehensive tests:
- Unit tests for each service
- Integration tests for factory
- Example tests for documentation

Run tests with:
```bash
go test ./internal/security/token -v
```

## Architecture

The token system follows a clean architecture pattern:

```
┌─────────────────┐
│   Factory       │ ← Configuration-driven service creation
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ TokenService    │ ← Unified interface for all token types
│ Interface       │
└─────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌─────────┐ ┌─────────┐
│ JWT     │ │ Paseto  │ ← Concrete implementations
│ Service │ │ Service │
└─────────┘ └─────────┘
```

This design allows for:
- Easy addition of new token formats
- Consistent API across different token types
- Configuration-driven behavior
- Testable and maintainable code