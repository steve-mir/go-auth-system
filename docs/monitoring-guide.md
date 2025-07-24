# Go Auth System - Comprehensive Monitoring Guide

## Overview

The Go Auth System includes a comprehensive monitoring, logging, and observability solution that tracks every aspect of your authentication service. This guide explains how to use, configure, and extend the monitoring capabilities.

## Features

### 🔍 **Comprehensive Tracking**
- HTTP request/response metrics
- Authentication events and success rates
- MFA operations and security events
- Database performance and connection pooling
- Cache hit/miss rates and performance
- Error tracking with categorization
- Distributed tracing across services
- Real-time log aggregation and analysis

### 📊 **Metrics Collection**
- Prometheus-compatible metrics
- Custom business metrics
- Performance indicators
- Security event tracking
- User activity monitoring

### 🚨 **Alerting & Error Tracking**
- Automatic error categorization
- Alert rule configuration
- Real-time error notifications
- Error resolution tracking

### 📈 **Visualization**
- Pre-built Grafana dashboards
- Real-time monitoring views
- Historical trend analysis
- Custom metric visualization

## Quick Start

### 1. Enable Monitoring in Configuration

```yaml
# config.yaml
external:
  monitoring:
    enabled: true
    prometheus:
      enabled: true
      port: 9090
      path: "/metrics"
  logging:
    level: "info"
    format: "json"
    output: "stdout"

monitoring:
  error_tracker:
    enabled: true
    max_errors: 10000
    retention_period: "24h"
    alerting_enabled: true
  log_aggregator:
    enabled: true
    max_entries: 100000
    retention_period: "7d"
    pattern_detection: true
  tracing:
    enabled: true
    service_name: "go-auth-system"
    service_version: "1.0.0"
    sample_rate: 0.1
```

### 2. Start the Service

```bash
# Start with monitoring enabled
./go-auth-system -config config.yaml
```

### 3. Access Monitoring Endpoints

```bash
# Prometheus metrics
curl http://localhost:9090/metrics

# System health with monitoring details
curl http://localhost:8080/monitoring/health

# Error tracking
curl http://localhost:8080/monitoring/errors

# Log aggregation
curl http://localhost:8080/monitoring/logs

# System statistics
curl http://localhost:8080/monitoring/stats
```

## Monitoring Endpoints

### Core Monitoring Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/monitoring/metrics` | GET | Prometheus metrics |
| `/monitoring/health` | GET | Detailed health check |
| `/monitoring/stats` | GET | System statistics |

### Error Tracking Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/monitoring/errors` | GET | List tracked errors |
| `/monitoring/errors/{id}` | GET | Error details |
| `/monitoring/errors/{id}/resolve` | POST | Mark error as resolved |

### Log Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/monitoring/logs` | GET | Retrieve log entries |
| `/monitoring/logs/search` | GET | Search logs |
| `/monitoring/logs/patterns` | GET | Detected log patterns |
| `/monitoring/logs/stats` | GET | Log statistics |

### Alert Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/monitoring/alerts` | GET | List alerts |
| `/monitoring/alerts/rules` | POST | Create alert rule |
| `/monitoring/alerts/rules/{id}` | DELETE | Delete alert rule |

## Metrics Reference

### HTTP Metrics

```prometheus
# Request rate by method and endpoint
http_requests_total{method="POST", endpoint="/api/v1/auth/login", status_code="200"}

# Request duration percentiles
http_duration_seconds{method="POST", endpoint="/api/v1/auth/login", quantile="0.95"}

# Request/response sizes
http_request_size_bytes{method="POST", endpoint="/api/v1/auth/login"}
http_response_size_bytes{method="POST", endpoint="/api/v1/auth/login"}
```

### Authentication Metrics

```prometheus
# Authentication attempts and results
auth_attempts_total{method="password", result="success"}
auth_successes_total{method="password", user_type="regular"}
auth_failures_total{method="password", reason="invalid_credentials"}

# Authentication duration
auth_duration_seconds{method="password", result="success", quantile="0.95"}

# Token operations
token_generations_total{token_type="access_token"}
token_validations_total{token_type="access_token", result="success"}
token_refreshes_total{result="success"}
```

### MFA Metrics

```prometheus
# MFA attempts and results
mfa_attempts_total{method="totp"}
mfa_successes_total{method="totp"}
mfa_failures_total{method="totp", reason="invalid_code"}
```

### Database Metrics

```prometheus
# Database connections
database_connections{state="active"}
database_connections{state="idle"}
database_connections{state="max"}

# Query performance
database_query_duration_seconds{operation="select", table="users", quantile="0.95"}
database_queries_total{operation="select", table="users"}
database_errors_total{operation="select", error_type="timeout"}
```

### Cache Metrics

```prometheus
# Cache operations
cache_hits_total{cache_type="session", operation="get"}
cache_misses_total{cache_type="session", operation="get"}
cache_operations_total{cache_type="session", operation="set", result="success"}
cache_operation_duration_seconds{cache_type="session", operation="get", quantile="0.95"}
```

### System Metrics

```prometheus
# Active sessions
active_sessions{session_type="user"}

# System health
system_health{component="database"}
system_health{component="redis"}
```

## Event Types and Categories

### Authentication Events

```json
{
  "event_type": "auth_event",
  "operation": "login",
  "user_id": "user-123",
  "success": true,
  "method": "password",
  "duration_ms": 150,
  "ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Security Events

```json
{
  "event_type": "security_event",
  "event": "failed_login",
  "severity": "medium",
  "user_id": "user-123",
  "ip": "192.168.1.100",
  "details": {
    "reason": "invalid_password",
    "attempts": 3
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### User Events

```json
{
  "event_type": "user_event",
  "operation": "profile_updated",
  "user_id": "user-123",
  "details": {
    "fields_updated": ["first_name", "phone"],
    "duration_ms": 200
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Events

```json
{
  "event_type": "error_event",
  "error_id": "err-456",
  "category": "service",
  "severity": "high",
  "operation": "create_user",
  "component": "user_service",
  "error_message": "Database connection timeout",
  "stack_trace": "...",
  "context": {
    "user_id": "user-123",
    "request_id": "req-789"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Error Categories and Severities

### Error Categories

- `auth` - Authentication-related errors
- `validation` - Input validation errors
- `service` - Business logic errors
- `database` - Database operation errors
- `cache` - Cache operation errors
- `network` - Network communication errors
- `system` - System-level errors

### Error Severities

- `low` - Minor issues that don't affect functionality
- `medium` - Issues that may impact some users
- `high` - Significant issues affecting multiple users
- `critical` - System-wide issues requiring immediate attention

## Distributed Tracing

### Trace Context

Every request creates a trace with the following information:

```json
{
  "trace_id": "trace-123",
  "span_id": "span-456",
  "operation": "user_login",
  "start_time": "2024-01-15T10:30:00Z",
  "duration": "150ms",
  "tags": {
    "user_id": "user-123",
    "method": "password",
    "ip": "192.168.1.100"
  },
  "logs": [
    {
      "timestamp": "2024-01-15T10:30:00.050Z",
      "level": "info",
      "message": "Validating credentials",
      "fields": {"step": "validation"}
    }
  ]
}
```

### Correlation Context

Requests are correlated across services using:

```json
{
  "correlation_id": "corr-789",
  "request_id": "req-123",
  "session_id": "sess-456",
  "user_id": "user-123",
  "client_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

## Log Aggregation and Analysis

### Log Patterns

The system automatically detects common log patterns:

```json
{
  "pattern_id": "pattern-123",
  "pattern": "User login failed: invalid credentials",
  "event_type": "auth_event",
  "component": "auth_service",
  "count": 150,
  "frequency": 2.5,
  "severity": "medium",
  "first_seen": "2024-01-15T09:00:00Z",
  "last_seen": "2024-01-15T10:30:00Z"
}
```

### Log Statistics

```json
{
  "total_entries": 50000,
  "level_counts": {
    "error": 500,
    "warn": 2000,
    "info": 45000,
    "debug": 2500
  },
  "event_counts": {
    "auth_event": 15000,
    "user_event": 8000,
    "security_event": 1200
  },
  "error_rate_percent": 1.0,
  "avg_duration_ms": 125.5
}
```

## Grafana Dashboard Setup

### 1. Import Dashboard

```bash
# Copy the dashboard configuration
cp grafana/dashboards/go-auth-system-dashboard.json /path/to/grafana/dashboards/

# Or import via Grafana UI
# Dashboard ID: go-auth-system-monitoring
```

### 2. Configure Data Sources

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'go-auth-system'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 5s
    metrics_path: /metrics
```

### 3. Dashboard Panels

The dashboard includes:

- **System Overview**: Service status and health
- **HTTP Metrics**: Request rates, response times, status codes
- **Authentication**: Login success rates, MFA usage
- **Database**: Query performance, connection pooling
- **Cache**: Hit rates, operation latencies
- **Errors**: Error rates by category and severity
- **Security**: Failed login attempts, suspicious activity
- **User Activity**: Registrations, logins, profile updates

## Alerting Configuration

### Example Alert Rules

```yaml
# prometheus-alerts.yml
groups:
  - name: go-auth-system
    rules:
      - alert: HighErrorRate
        expr: rate(errors_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors/sec"

      - alert: AuthenticationFailures
        expr: rate(auth_failures_total[5m]) > 0.5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "High authentication failure rate"
          description: "Auth failure rate is {{ $value }} failures/sec"

      - alert: DatabaseConnectionIssues
        expr: database_connections{state="active"} / database_connections{state="max"} > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool nearly exhausted"
          description: "{{ $value }}% of database connections in use"
```

## Performance Optimization

### Monitoring Overhead

The monitoring system is designed to have minimal performance impact:

- **Metrics Collection**: < 1ms overhead per request
- **Log Aggregation**: Asynchronous processing
- **Error Tracking**: Efficient in-memory storage
- **Tracing**: Configurable sampling rate

### Configuration Tuning

```yaml
monitoring:
  # Reduce memory usage
  error_tracker:
    max_errors: 5000
    retention_period: "12h"
  
  log_aggregator:
    max_entries: 50000
    retention_period: "3d"
  
  # Reduce tracing overhead
  tracing:
    sample_rate: 0.05  # Sample 5% of requests
```

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Reduce `max_errors` and `max_entries` in configuration
   - Decrease retention periods
   - Enable cleanup routines

2. **Missing Metrics**
   - Check Prometheus scrape configuration
   - Verify metrics endpoint accessibility
   - Review service logs for errors

3. **Dashboard Not Loading**
   - Verify Grafana data source configuration
   - Check Prometheus connectivity
   - Review dashboard JSON syntax

### Debug Commands

```bash
# Check monitoring health
curl http://localhost:8080/monitoring/health

# View current metrics
curl http://localhost:8080/monitoring/metrics | grep auth_

# Check error tracking
curl http://localhost:8080/monitoring/errors?category=auth

# View log patterns
curl http://localhost:8080/monitoring/logs/patterns
```

## Extending Monitoring

### Adding Custom Metrics

```go
// Add custom business metric
func (s *Server) trackCustomEvent(ctx context.Context, event string, value float64) {
    if s.monitoring != nil {
        s.monitoring.GetMetrics().RecordCustomMetric(event, value)
    }
}
```

### Custom Alert Rules

```go
// Add custom alert rule
rule := &monitoring.AlertRule{
    Name:       "CustomBusinessRule",
    Category:   monitoring.ErrorCategoryBusiness,
    Severity:   monitoring.ErrorSeverityMedium,
    Threshold:  10,
    TimeWindow: 5 * time.Minute,
}

s.monitoring.GetErrorTracker().AddAlertRule(rule)
```

### Custom Log Patterns

```go
// Track custom log pattern
entry := monitoring.LogEntry{
    Timestamp: time.Now(),
    Level:     "info",
    Message:   "Custom business event occurred",
    EventType: "business_event",
    Component: "custom_service",
    Fields: map[string]interface{}{
        "event_id": "evt-123",
        "value":    42.0,
    },
}

s.monitoring.GetLogAggregator().AddLogEntry(entry)
```

## Best Practices

### 1. Metric Naming
- Use consistent naming conventions
- Include units in metric names
- Group related metrics with prefixes

### 2. Error Handling
- Always track errors with appropriate categories
- Include sufficient context for debugging
- Use appropriate severity levels

### 3. Performance
- Use sampling for high-volume tracing
- Configure appropriate retention periods
- Monitor monitoring system resource usage

### 4. Security
- Sanitize sensitive data in logs
- Use correlation IDs instead of user data
- Implement proper access controls for monitoring endpoints

### 5. Alerting
- Set meaningful thresholds
- Avoid alert fatigue with proper grouping
- Include actionable information in alerts

## Conclusion

The comprehensive monitoring system provides complete visibility into your Go Auth System's performance, security, and reliability. Use this guide to configure, customize, and extend the monitoring capabilities to meet your specific requirements.

For additional support or questions, refer to the system logs or monitoring endpoints for real-time diagnostics.