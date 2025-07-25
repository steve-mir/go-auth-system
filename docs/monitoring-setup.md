# Monitoring Setup Guide

This guide explains how to set up and use the monitoring stack for the Go Auth System.

## Quick Start

### Docker Compose (Recommended for Development)

1. **Start the monitoring stack:**
   ```bash
   docker-compose --profile monitoring up -d
   ```

2. **Access the services:**
   - **Go Auth System**: http://localhost:8080
   - **Prometheus**: http://localhost:9091
   - **Grafana**: http://localhost:3000 (admin/admin)

3. **Stop the monitoring stack:**
   ```bash
   docker-compose --profile monitoring down
   ```

### Kubernetes (Production)

1. **Deploy the monitoring stack:**
   ```bash
   kubectl apply -f k8s/
   ```

2. **Access Grafana (port-forward):**
   ```bash
   kubectl port-forward -n go-auth-system svc/grafana 3000:3000
   ```

## What's Included

### Metrics Collection
- **Application Metrics**: HTTP requests, response times, error rates
- **Database Metrics**: Connection pool usage, query performance
- **Cache Metrics**: Redis hit/miss rates, memory usage
- **System Metrics**: CPU, memory, disk usage

### Dashboards
- **Go Auth System Dashboard**: Comprehensive overview of system health
- **Authentication Metrics**: Login success/failure rates, MFA usage
- **Performance Metrics**: Response times, throughput, error rates
- **Infrastructure Metrics**: Database and cache performance

### Alerting Rules
- High error rate (>10% for 2 minutes)
- High authentication failure rate (>50% for 1 minute)
- Database connection pool usage (>80% for 5 minutes)
- High response time (95th percentile >1s for 5 minutes)
- Service down (>1 minute)

## Configuration Files

### Docker Compose
- `docker/prometheus.yml` - Prometheus configuration
- `docker/go-auth-system-alerts.yml` - Alert rules
- `grafana/provisioning/` - Grafana auto-configuration

### Kubernetes
- `k8s/monitoring.yaml` - ServiceMonitor and ConfigMaps
- Includes Prometheus, Grafana, and alert configurations

## Customization

### Adding Custom Metrics
1. Add metrics to your Go application using Prometheus client
2. Update the dashboard JSON file
3. Restart the monitoring stack

### Custom Alerts
1. Edit `docker/go-auth-system-alerts.yml` (Docker)
2. Or update `k8s/monitoring.yaml` (Kubernetes)
3. Restart Prometheus

### Dashboard Modifications
1. Edit `grafana/dashboards/go-auth-system-dashboard.json`
2. Or modify through Grafana UI and export

## Troubleshooting

### Common Issues

**Grafana shows "No data":**
- Check if Prometheus is scraping metrics: http://localhost:9091/targets
- Verify your application is exposing metrics on port 8081

**Prometheus can't reach the application:**
- Ensure the application is running and healthy
- Check Docker network connectivity
- Verify the metrics endpoint is accessible

**Dashboard not loading automatically:**
- Check Grafana logs: `docker-compose logs grafana`
- Verify provisioning files are mounted correctly

### Health Checks

```bash
# Check if metrics are being exposed
curl http://localhost:8081/metrics

# Check Prometheus targets
curl http://localhost:9091/api/v1/targets

# Check Grafana health
curl http://localhost:3000/api/health
```

## Production Considerations

### Security
- Change default Grafana password
- Enable HTTPS for all services
- Restrict network access to monitoring services
- Use proper authentication for Prometheus

### Performance
- Adjust scrape intervals based on load
- Configure appropriate retention periods
- Monitor resource usage of monitoring stack itself

### High Availability
- Deploy Prometheus in HA mode
- Use external storage for Grafana
- Set up alerting redundancy

## Metrics Reference

### Application Metrics
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request duration histogram
- `auth_attempts_total` - Authentication attempts
- `auth_failures_total` - Authentication failures
- `database_connections` - Database connection pool metrics
- `cache_operations_total` - Cache hit/miss counters

### System Metrics
- `process_cpu_seconds_total` - CPU usage
- `process_resident_memory_bytes` - Memory usage
- `go_memstats_*` - Go runtime metrics