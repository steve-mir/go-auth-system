# Health Check Endpoints

The go-auth-system provides comprehensive health check endpoints for monitoring and orchestration purposes.

## Available Endpoints

### 1. Overall Health Check
- **URL**: `/health`
- **Method**: GET
- **Description**: Returns the overall health status of all system components
- **Response Codes**:
  - `200 OK`: System is healthy or degraded
  - `503 Service Unavailable`: System is unhealthy

**Example Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "components": {
    "database": {
      "status": "healthy",
      "message": "Connected (pool: 2/25)",
      "timestamp": "2024-01-15T10:30:00Z",
      "duration_ms": 5
    },
    "liveness": {
      "status": "healthy",
      "message": "Application is alive",
      "timestamp": "2024-01-15T10:30:00Z",
      "duration_ms": 1
    },
    "readiness": {
      "status": "healthy",
      "message": "All components ready",
      "timestamp": "2024-01-15T10:30:00Z",
      "duration_ms": 6
    }
  }
}
```

### 2. Liveness Probe
- **URL**: `/health/live`
- **Method**: GET
- **Description**: Simple liveness check to verify the application is running
- **Response Codes**: Always `200 OK` if the application is running

**Example Response:**
```json
{
  "status": "alive",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 3. Readiness Probe
- **URL**: `/health/ready`
- **Method**: GET
- **Description**: Checks if the application is ready to serve requests
- **Response Codes**:
  - `200 OK`: Application is ready
  - `503 Service Unavailable`: Application is not ready

**Example Response (Ready):**
```json
{
  "status": "ready",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Example Response (Not Ready):**
```json
{
  "status": "not_ready",
  "timestamp": "2024-01-15T10:30:00Z",
  "reason": "One or more components are unhealthy"
}
```

## Health Status Values

- **healthy**: Component is functioning normally
- **degraded**: Component is functioning but with reduced performance
- **unhealthy**: Component is not functioning properly

## Monitored Components

### Database
- **Component Name**: `database`
- **Checks**:
  - Connection availability
  - Connection pool status
  - Query execution capability

### Liveness
- **Component Name**: `liveness`
- **Checks**:
  - Basic application responsiveness

### Readiness
- **Component Name**: `readiness`
- **Checks**:
  - All critical components are healthy
  - Application can serve requests

## Kubernetes Integration

These endpoints are designed to work with Kubernetes health checks:

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: go-auth-system
    image: go-auth-system:latest
    ports:
    - containerPort: 8080
    livenessProbe:
      httpGet:
        path: /health/live
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /health/ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
```

## Docker Compose Integration

The health checks are also configured in the Docker Compose setup:

```yaml
services:
  app:
    # ... other configuration
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

## Monitoring and Alerting

You can use these endpoints with monitoring systems like:

- **Prometheus**: Scrape the `/health` endpoint for metrics
- **Grafana**: Create dashboards based on health status
- **Nagios/Zabbix**: Monitor endpoint availability and response codes
- **Load Balancers**: Use readiness probe for traffic routing decisions

## Troubleshooting

### Common Issues

1. **Database Unhealthy**
   - Check database connectivity
   - Verify connection pool configuration
   - Check database server status

2. **Application Not Ready**
   - Check all component health statuses
   - Verify configuration settings
   - Check application logs for errors

3. **Slow Health Check Response**
   - Check database query performance
   - Verify network connectivity
   - Review connection pool settings