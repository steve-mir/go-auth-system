# Redis Repository Package

This package provides Redis-based implementations for caching, session management, rate limiting, and token blacklisting functionality for the authentication system.

## Components

### 1. Connection Management (`connection.go`)

Provides Redis client connection with connection pooling:

```go
cfg := &config.RedisConfig{
    Host:         "localhost",
    Port:         6379,
    DB:           0,
    PoolSize:     10,
    MinIdleConns: 2,
    DialTimeout:  5 * time.Second,
    ReadTimeout:  3 * time.Second,
    WriteTimeout: 3 * time.Second,
}

client, err := redis.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

### 2. Session Storage (`session.go`)

Manages user sessions with automatic expiration:

```go
store := redis.NewSessionStore(client)

// Store session
sessionData := &redis.SessionData{
    UserID:    "user123",
    Roles:     []string{"user", "admin"},
    IPAddress: "192.168.1.1",
    UserAgent: "Mozilla/5.0...",
    CreatedAt: time.Now(),
    LastUsed:  time.Now(),
}

err := store.Store(ctx, "session-id", sessionData, time.Hour)

// Retrieve session
data, err := store.Get(ctx, "session-id")

// Update session
err = store.Update(ctx, "session-id", sessionData, time.Hour)

// Delete session
err = store.Delete(ctx, "session-id")
```

### 3. Rate Limiting (`rate_limiter.go`)

Implements sliding window rate limiting:

```go
limiter := redis.NewRateLimiter(client, time.Minute)

// Check if request is allowed
result, err := limiter.Allow(ctx, "user:123", 100) // 100 requests per minute
if err != nil {
    return err
}

if !result.Allowed {
    // Rate limit exceeded
    return fmt.Errorf("rate limit exceeded, retry after %v", result.RetryAfter)
}

// Process request...
```

#### Account Lockout

Progressive account lockout for failed login attempts:

```go
lockout := redis.NewAccountLockout(client)

// Record failed attempt
result, err := lockout.RecordFailedAttempt(ctx, "user:123", 5, time.Hour)
if err != nil {
    return err
}

if result.Blocked {
    return fmt.Errorf("account locked until %v", result.Until)
}

// Check if account is blocked
blocked, err := lockout.IsBlocked(ctx, "user:123")
if blocked.Blocked {
    return fmt.Errorf("account locked")
}

// Clear failed attempts after successful login
err = lockout.ClearFailedAttempts(ctx, "user:123")
```

### 4. Token Blacklist (`token_blacklist.go`)

Manages blacklisted tokens with TTL cleanup:

```go
blacklist := redis.NewTokenBlacklist(client)

// Blacklist a token
err := blacklist.BlacklistToken(ctx, token, userID, expiresAt, "user logout", "access")

// Check if token is blacklisted
isBlacklisted, blacklistedToken, err := blacklist.IsBlacklisted(ctx, token)
if isBlacklisted {
    return fmt.Errorf("token is blacklisted: %s", blacklistedToken.Reason)
}

// Remove token from blacklist
err = blacklist.RemoveToken(ctx, token)

// Get all blacklisted tokens for a user
userTokens, err := blacklist.GetUserBlacklistedTokens(ctx, userID)
```

## Configuration

Redis configuration is managed through the `config.RedisConfig` struct:

```yaml
redis:
  host: localhost
  port: 6379
  password: ""
  db: 0
  pool_size: 10
  min_idle_conns: 2
  dial_timeout: 5s
  read_timeout: 3s
  write_timeout: 3s
```

## Testing

### Unit Tests

Run unit tests for individual components:

```bash
go test ./internal/repository/redis -v
```

### Integration Tests

Run integration tests (requires Redis server):

```bash
go test ./internal/repository/redis -tags=integration -v
```

## Key Features

### Connection Pooling
- Configurable pool size and idle connections
- Automatic connection health checks
- Connection statistics monitoring

### Session Management
- Automatic expiration with TTL
- Session extension and refresh
- User session enumeration and cleanup
- Concurrent session support

### Rate Limiting
- Sliding window algorithm
- Per-key rate limiting
- Configurable window size and limits
- Atomic operations using Lua scripts

### Account Security
- Progressive lockout policies
- Configurable attempt thresholds
- Automatic lockout expiration
- Manual account unlock

### Token Security
- SHA-256 token hashing for storage
- Automatic TTL cleanup
- Token categorization (access/refresh)
- Bulk operations for user tokens

## Performance Considerations

### Memory Usage
- Sessions and blacklisted tokens use JSON serialization
- Rate limiting uses sorted sets for efficient time-based operations
- Automatic cleanup of expired data

### Network Efficiency
- Connection pooling reduces connection overhead
- Lua scripts minimize round trips for complex operations
- Pipelining support for batch operations

### Scalability
- Stateless design supports horizontal scaling
- Distributed rate limiting across instances
- Efficient key patterns for data organization

## Error Handling

All operations return descriptive errors:
- Connection errors
- Serialization/deserialization errors
- Key validation errors
- TTL and expiration errors

## Security

### Data Protection
- Token hashing prevents token exposure in Redis
- Configurable key prefixes for namespace isolation
- Automatic cleanup of sensitive data

### Access Control
- Redis AUTH support through configuration
- TLS connection support
- Network-level security through Redis configuration

## Monitoring

### Health Checks
```go
err := client.Health(ctx)
if err != nil {
    // Redis is unhealthy
}
```

### Statistics
```go
stats := client.GetStats()
log.Printf("Pool stats: Total=%d, Idle=%d", stats.TotalConns, stats.IdleConns)

// Token blacklist statistics
blacklistStats, err := blacklist.GetStats(ctx)
```

## Best Practices

1. **Connection Management**: Always close Redis clients when done
2. **Context Usage**: Use context for timeout and cancellation
3. **Error Handling**: Check all Redis operation errors
4. **TTL Management**: Set appropriate TTLs for all cached data
5. **Key Naming**: Use consistent key prefixes and patterns
6. **Cleanup**: Implement periodic cleanup for expired data
7. **Monitoring**: Monitor Redis memory usage and connection pool stats