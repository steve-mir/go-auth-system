#!/bin/bash

# Go Auth System - Monitoring Stack Startup Script

set -e

echo "🚀 Starting Go Auth System with Monitoring Stack..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Function to wait for service to be ready
wait_for_service() {
    local service_name=$1
    local port=$2
    local max_attempts=30
    local attempt=1
    
    echo "⏳ Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "http://localhost:$port/health" > /dev/null 2>&1 || \
           curl -f -s "http://localhost:$port" > /dev/null 2>&1; then
            echo "✅ $service_name is ready!"
            return 0
        fi
        
        echo "   Attempt $attempt/$max_attempts - $service_name not ready yet..."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo "❌ $service_name failed to start within expected time"
    return 1
}

# Start the monitoring stack
echo "📊 Starting monitoring services..."
docker-compose --profile monitoring up -d

echo "⏳ Waiting for services to start..."
sleep 10

# Check service health
echo "🔍 Checking service health..."

# Wait for main application
if wait_for_service "Go Auth System" 8080; then
    echo "✅ Main application is running"
else
    echo "❌ Main application failed to start"
    exit 1
fi

# Wait for Prometheus
if wait_for_service "Prometheus" 9091; then
    echo "✅ Prometheus is running"
else
    echo "❌ Prometheus failed to start"
fi

# Wait for Grafana
if wait_for_service "Grafana" 3000; then
    echo "✅ Grafana is running"
else
    echo "❌ Grafana failed to start"
fi

echo ""
echo "🎉 Monitoring stack is ready!"
echo ""
echo "📊 Access your services:"
echo "   • Go Auth System: http://localhost:8080"
echo "   • Prometheus:     http://localhost:9091"
echo "   • Grafana:        http://localhost:3000 (admin/admin)"
echo ""
echo "📈 Your dashboard should be automatically loaded in Grafana!"
echo ""
echo "🔧 To stop the monitoring stack:"
echo "   docker-compose --profile monitoring down"
echo ""