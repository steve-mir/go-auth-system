# Password Hashing Service

This package provides a configurable password hashing service that supports both Argon2id and bcrypt algorithms. The service is designed to be secure, performant, and easy to use with configuration-driven algorithm selection.

## Features

- **Dual Algorithm Support**: Argon2id and bcrypt implementations
- **Configuration-Driven**: Algorithm selection and parameters via configuration
- **Secure by Default**: Strong default parameters for both algorithms
- **Rehash Detection**: Automatic detection when passwords need rehashing due to parameter changes
- **Comprehensive Testing**: Full test coverage with benchmarks
- **Thread-Safe**: Safe for concurrent use

## Supported Algorithms

### Argon2id
- **Recommended for new applications**
- Memory-hard function resistant to GPU attacks
- Configurable memory, iterations, parallelism, salt length, and key length
- PHC string format output

### bcrypt
- **Widely supported and battle-tested**
- Configurable cost parameter
- Standard bcrypt format output
- Good for compatibility with existing systems

## Usage

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/steve-mir/go-auth-system/internal/config"
    "github.com/steve-mir/go-auth-system/internal/security/hash"
)

func main() {
    // Configure Argon2 hashing
    cfg := config.PasswordHashConfig{
        Algorithm: "argon2",
        Argon2: config.Argon2Config{
            Memory:      64 * 1024, // 64 MB
            Iterations:  3,
            Parallelism: 2,
            SaltLength:  16,
            KeyLength:   32,
        },
    }

    // Create factory and hash service
    factory := hash.NewFactory(cfg)
    service, err := factory.CreateHashService()
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    password := "mySecurePassword123"

    // Hash the password
    hashedPassword, err := service.HashPassword(ctx, password)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Hashed password: %s\n", hashedPassword)

    // Verify the password
    err = service.VerifyPassword(ctx, password, hashedPassword)
    if err != nil {
        fmt.Printf("Password verification failed: %v\n", err)
    } else {
        fmt.Println("Password verified successfully")
    }

    // Check if rehash is needed
    if service.NeedsRehash(ctx, hashedPassword) {
        fmt.Println("Password needs rehashing")
    }
}
```

### Configuration Examples

#### Argon2id Configuration

```go
cfg := config.PasswordHashConfig{
    Algorithm: "argon2",
    Argon2: config.Argon2Config{
        Memory:      64 * 1024, // Memory in KB (64 MB)
        Iterations:  3,         // Number of iterations
        Parallelism: 2,         // Degree of parallelism
        SaltLength:  16,        // Salt length in bytes
        KeyLength:   32,        // Output key length in bytes
    },
}
```

#### bcrypt Configuration

```go
cfg := config.PasswordHashConfig{
    Algorithm: "bcrypt",
    Bcrypt: config.BcryptConfig{
        Cost: 12, // Cost parameter (4-31)
    },
}
```

### Using Recommended Configurations

```go
// Get recommended configuration
factory := hash.NewFactory(config.PasswordHashConfig{Algorithm: "argon2"})
recommended := factory.GetRecommendedConfig()

// Create service with recommended config
newFactory := hash.NewFactory(recommended)
service, err := newFactory.CreateHashService()
```

### Configuration Validation

```go
factory := hash.NewFactory(cfg)
if err := factory.ValidateConfig(); err != nil {
    log.Fatalf("Invalid configuration: %v", err)
}
```

## Security Considerations

### Argon2id Parameters

- **Memory**: Higher values increase resistance to GPU attacks (minimum 1024 KB)
- **Iterations**: Higher values increase time cost (minimum 1)
- **Parallelism**: Should match available CPU cores (minimum 1)
- **Salt Length**: Minimum 8 bytes, recommended 16 bytes
- **Key Length**: Minimum 16 bytes, recommended 32 bytes

### bcrypt Parameters

- **Cost**: Higher values increase time cost (range 4-31)
- Cost 12 is recommended for most applications
- Each increment doubles the computation time

### Password Requirements

- Minimum length: 8 characters
- Maximum length: 128 characters
- All Unicode characters are supported

## Performance

### Benchmarks

The service includes comprehensive benchmarks for both algorithms:

```bash
go test -bench=. ./internal/security/hash/
```

### Typical Performance (on modern hardware)

- **Argon2id** (64MB, 3 iterations, 2 parallelism): ~100ms
- **bcrypt** (cost 12): ~250ms

## Error Handling

The service provides specific error types for different failure scenarios:

- `ErrPasswordTooShort`: Password is shorter than 8 characters
- `ErrPasswordTooLong`: Password is longer than 128 characters
- `ErrInvalidHash`: Hash format is invalid
- `ErrHashMismatch`: Password doesn't match the hash
- `ErrHashingFailed`: Hashing operation failed

## Thread Safety

All hash services are thread-safe and can be used concurrently from multiple goroutines.

## Testing

The package includes comprehensive tests covering:

- Password hashing and verification
- Error conditions
- Configuration validation
- Rehash detection
- Performance benchmarks
- Integration tests

Run tests with:

```bash
go test ./internal/security/hash/... -v
```

## Migration Between Algorithms

When migrating from one algorithm to another:

1. Update configuration to new algorithm
2. Use `NeedsRehash()` to identify passwords that need updating
3. Rehash passwords during user login (when plaintext is available)
4. Maintain backward compatibility during transition period

## Integration with Authentication System

The hash service integrates with the broader authentication system through:

- Configuration system for algorithm selection
- Factory pattern for service creation
- Standard interface for consistent usage
- Error types compatible with API error handling