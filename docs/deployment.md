# Deployment Guide

This guide covers the various deployment options for the go-auth-system, including Docker, Docker Compose, Kubernetes, and Helm deployments.

## Overview

The go-auth-system supports multiple deployment patterns:

- **Docker**: Single container deployment for development and testing
- **Docker Compose**: Multi-container stack for local development
- **Kubernetes**: Production-ready orchestrated deployment
- **Helm**: Flexible Kubernetes deployment with configuration management

## Prerequisites

### Common Requirements
- Go 1.23.1 or later
- Docker and Docker Compose
- Make (for using Makefile commands)

### Kubernetes Deployments
- kubectl configured with cluster access
- Kubernetes cluster (1.24+)
- Ingress controller (nginx recommended)
- cert-manager (for TLS certificates)

### Helm Deployments
- Helm 3.0+
- kubectl configured with cluster access

## Quick Start

### Using Make Commands

```bash
# Build and deploy with Docker
make deploy-docker

# Deploy with Docker Compose
make deploy-compose

# Deploy to Kubernetes
make deploy-k8s

# Deploy with Helm
make deploy-helm

# Clean all deployments
make clean-deployments

# Run deployment tests
make test-deployment
```

### Using Deployment Script

```bash
# Make script executable (if needed)
chmod +x scripts/deploy.sh

# Deploy with Docker
./scripts/deploy.sh docker --image-tag latest

# Deploy with Docker Compose
./scripts/deploy.sh compose --wait

# Deploy to Kubernetes
./scripts/deploy.sh k8s --namespace production --wait

# Deploy with Helm
./scripts/deploy.sh helm --release-name auth-prod --wait

# Clean up deployments
./scripts/deploy.sh clean all
```

## Docker Deployment

### Single Container

```bash
# Build the image
docker build -t go-auth-system:latest .

# Run the container
docker run -d \
  --name go-auth-system \
  -p 8080:8080 \
  -p 9090:9090 \
  -p 8081:8081 \
  -e ENVIRONMENT=production \
  -e LOG_LEVEL=info \
  go-auth-system:latest
```

### Environment Variables

Key environment variables for Docker deployment:

```bash
# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_system
DB_USER=postgres
DB_PASSWORD=postgres
DB_SSL_MODE=disable

# Redis configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Security configuration
JWT_SIGNING_KEY=your-signing-key
JWT_ENCRYPTION_KEY=your-encryption-key
ENCRYPTION_MASTER_KEY=your-master-key

# Application configuration
ENVIRONMENT=production
LOG_LEVEL=info
LOG_FORMAT=json

# Feature flags
ADMIN_DASHBOARD_ENABLED=true
MONITORING_ENABLED=true
AUDIT_LOGGING_ENABLED=true
```

## Docker Compose Deployment

### Basic Stack

```bash
# Start the full stack
docker-compose up -d

# With monitoring (Prometheus & Grafana)
docker-compose --profile monitoring up -d

# View logs
docker-compose logs -f

# Stop the stack
docker-compose down
```

### Services Included

- **app**: Main authentication service
- **postgres**: PostgreSQL database
- **redis**: Redis cache
- **prometheus**: Metrics collection (optional)
- **grafana**: Monitoring dashboards (optional)

### Accessing Services

- REST API: http://localhost:8080
- gRPC API: localhost:9090
- Metrics: http://localhost:8081/metrics
- Prometheus: http://localhost:9091 (with monitoring profile)
- Grafana: http://localhost:3000 (with monitoring profile)

## Kubernetes Deployment

### Manual Deployment

```bash
# Create namespace
kubectl create namespace go-auth-system

# Apply all manifests
kubectl apply -f k8s/ -n go-auth-system

# Check deployment status
kubectl get all -n go-auth-system

# Wait for deployment to be ready
kubectl wait --for=condition=available --timeout=300s deployment/go-auth-system -n go-auth-system
```

### Manifest Files

- `namespace.yaml`: Namespace definition
- `configmap.yaml`: Application configuration
- `secret.yaml`: Sensitive configuration (update with real values)
- `postgres-deployment.yaml`: PostgreSQL database
- `redis-deployment.yaml`: Redis cache
- `auth-deployment.yaml`: Main application
- `ingress.yaml`: External access configuration
- `monitoring.yaml`: Prometheus monitoring setup

### Configuration

Update `k8s/secret.yaml` with production values:

```bash
# Encode secrets in base64
echo -n "your-production-password" | base64

# Update secret.yaml with encoded values
kubectl apply -f k8s/secret.yaml -n go-auth-system
```

### Health Checks

The deployment includes comprehensive health checks:

- **Liveness Probe**: `/health/live` - Basic application health
- **Readiness Probe**: `/health/ready` - Ready to serve traffic
- **Startup Probe**: `/health/live` - Initial startup check

### Scaling

```bash
# Scale the deployment
kubectl scale deployment go-auth-system --replicas=5 -n go-auth-system

# Enable horizontal pod autoscaler
kubectl autoscale deployment go-auth-system --cpu-percent=70 --min=3 --max=10 -n go-auth-system
```

## Helm Deployment

### Installation

```bash
# Install with default values
helm install go-auth-system ./helm/go-auth-system

# Install with custom values
helm install go-auth-system ./helm/go-auth-system \
  --namespace production \
  --create-namespace \
  --values custom-values.yaml

# Upgrade existing release
helm upgrade go-auth-system ./helm/go-auth-system \
  --namespace production
```

### Configuration

Create a custom values file:

```yaml
# custom-values.yaml
app:
  replicaCount: 5
  environment: production

ingress:
  enabled: true
  hosts:
    - host: auth.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
          port: http

secrets:
  database:
    password: "your-production-db-password"
  jwt:
    signing_key: "your-production-signing-key"
  encryption:
    master_key: "your-production-encryption-key"

postgresql:
  enabled: true
  auth:
    postgresPassword: "your-production-db-password"

redis:
  enabled: true

monitoring:
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
```

### Helm Commands

```bash
# List releases
helm list -n go-auth-system

# Get release status
helm status go-auth-system -n go-auth-system

# Get release values
helm get values go-auth-system -n go-auth-system

# Rollback release
helm rollback go-auth-system 1 -n go-auth-system

# Uninstall release
helm uninstall go-auth-system -n go-auth-system
```

## Monitoring and Observability

### Health Endpoints

- `/health` - Overall system health
- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe
- `/metrics` - Prometheus metrics

### Prometheus Metrics

Key metrics exposed:

- `http_requests_total` - HTTP request counter
- `http_request_duration_seconds` - Request duration histogram
- `database_connections_active` - Active database connections
- `redis_connections_active` - Active Redis connections
- `auth_login_attempts_total` - Login attempt counter
- `auth_login_failures_total` - Failed login counter

### Grafana Dashboards

When using the monitoring profile with Docker Compose or enabling monitoring in Helm:

- System metrics dashboard
- Application performance dashboard
- Authentication metrics dashboard
- Database and cache metrics

## Security Considerations

### Container Security

- Runs as non-root user (UID 1001)
- Read-only root filesystem
- No privileged escalation
- Minimal base image (Alpine)

### Kubernetes Security

- Security contexts configured
- Pod security policies
- Network policies (recommended)
- RBAC permissions
- Secret management

### Production Checklist

- [ ] Update all default passwords and keys
- [ ] Configure TLS certificates
- [ ] Set up proper ingress with rate limiting
- [ ] Configure monitoring and alerting
- [ ] Set up log aggregation
- [ ] Configure backup procedures
- [ ] Review and apply security policies
- [ ] Set up disaster recovery procedures

## Troubleshooting

### Common Issues

1. **Database Connection Issues**
   ```bash
   # Check database connectivity
   kubectl exec -it deployment/go-auth-system -n go-auth-system -- nc -zv postgres-service 5432
   ```

2. **Redis Connection Issues**
   ```bash
   # Check Redis connectivity
   kubectl exec -it deployment/go-auth-system -n go-auth-system -- nc -zv redis-service 6379
   ```

3. **Health Check Failures**
   ```bash
   # Check health endpoints
   kubectl exec -it deployment/go-auth-system -n go-auth-system -- curl http://localhost:8080/health
   ```

4. **Image Pull Issues**
   ```bash
   # Check image pull secrets
   kubectl get pods -n go-auth-system
   kubectl describe pod <pod-name> -n go-auth-system
   ```

### Logs

```bash
# Kubernetes logs
kubectl logs -f deployment/go-auth-system -n go-auth-system

# Docker Compose logs
docker-compose logs -f app

# Docker logs
docker logs -f go-auth-system
```

### Debug Mode

Enable debug logging:

```bash
# Environment variable
LOG_LEVEL=debug

# Kubernetes
kubectl set env deployment/go-auth-system LOG_LEVEL=debug -n go-auth-system
```

## Performance Tuning

### Resource Limits

Recommended resource limits for production:

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### Database Tuning

- Connection pooling: 25 max connections
- Connection lifetime: 5 minutes
- Idle connections: 5

### Redis Tuning

- Pool size: 10 connections
- Minimum idle: 5 connections
- Connection timeout: 5 seconds

## Backup and Recovery

### Database Backup

```bash
# Kubernetes
kubectl exec -n go-auth-system deployment/postgres -- pg_dump -U postgres auth_system > backup.sql

# Docker Compose
docker-compose exec postgres pg_dump -U postgres auth_system > backup.sql
```

### Database Restore

```bash
# Kubernetes
kubectl exec -i -n go-auth-system deployment/postgres -- psql -U postgres auth_system < backup.sql

# Docker Compose
docker-compose exec -T postgres psql -U postgres auth_system < backup.sql
```

## Support

For deployment issues:

1. Check the troubleshooting section above
2. Review application logs
3. Verify configuration values
4. Check resource availability
5. Consult the project documentation

## Contributing

To contribute to deployment configurations:

1. Test changes in a development environment
2. Update documentation
3. Add or update tests in `test/deployment/`
4. Submit a pull request with detailed description