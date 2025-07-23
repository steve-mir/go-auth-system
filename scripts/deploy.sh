#!/bin/bash

# Deployment script for go-auth-system
# Supports Docker, Docker Compose, Kubernetes, and Helm deployments

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="go-auth-system"
IMAGE_TAG="${IMAGE_TAG:-latest}"
NAMESPACE="${NAMESPACE:-go-auth-system}"
HELM_RELEASE_NAME="${HELM_RELEASE_NAME:-go-auth-system}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
    docker          Build and run Docker container
    compose         Deploy using Docker Compose
    k8s             Deploy to Kubernetes
    helm            Deploy using Helm
    clean           Clean up deployments
    test            Run deployment tests
    help            Show this help message

Options:
    --image-tag TAG     Docker image tag (default: latest)
    --namespace NS      Kubernetes namespace (default: go-auth-system)
    --release-name NAME Helm release name (default: go-auth-system)
    --dry-run          Show what would be deployed without actually deploying
    --wait             Wait for deployment to be ready
    --timeout SECONDS  Timeout for waiting (default: 300)

Examples:
    $0 docker --image-tag v1.0.0
    $0 compose
    $0 k8s --namespace production --wait
    $0 helm --release-name auth-prod --dry-run
    $0 clean k8s
    $0 test docker

EOF
}

# Check prerequisites
check_prerequisites() {
    local deployment_type=$1
    
    case $deployment_type in
        docker)
            if ! command -v docker &> /dev/null; then
                log_error "Docker is not installed or not in PATH"
                exit 1
            fi
            ;;
        compose)
            if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
                log_error "Docker Compose is not installed or not in PATH"
                exit 1
            fi
            ;;
        k8s)
            if ! command -v kubectl &> /dev/null; then
                log_error "kubectl is not installed or not in PATH"
                exit 1
            fi
            if ! kubectl cluster-info &> /dev/null; then
                log_error "Cannot connect to Kubernetes cluster"
                exit 1
            fi
            ;;
        helm)
            if ! command -v helm &> /dev/null; then
                log_error "Helm is not installed or not in PATH"
                exit 1
            fi
            if ! kubectl cluster-info &> /dev/null; then
                log_error "Cannot connect to Kubernetes cluster"
                exit 1
            fi
            ;;
    esac
}

# Build Docker image
build_docker_image() {
    log_info "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
    
    cd "$PROJECT_ROOT"
    docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .
    
    log_success "Docker image built successfully"
}

# Deploy with Docker
deploy_docker() {
    local dry_run=$1
    
    check_prerequisites docker
    
    if [[ "$dry_run" != "true" ]]; then
        build_docker_image
        
        log_info "Starting Docker container"
        docker run -d \
            --name go-auth-system \
            -p 8080:8080 \
            -p 9090:9090 \
            -p 8081:8081 \
            -e ENVIRONMENT=production \
            -e LOG_LEVEL=info \
            "${IMAGE_NAME}:${IMAGE_TAG}"
        
        log_success "Docker container started successfully"
        log_info "REST API: http://localhost:8080"
        log_info "gRPC API: localhost:9090"
        log_info "Metrics: http://localhost:8081/metrics"
    else
        log_info "Would build and run Docker container: ${IMAGE_NAME}:${IMAGE_TAG}"
    fi
}

# Deploy with Docker Compose
deploy_compose() {
    local dry_run=$1
    local wait_ready=$2
    
    check_prerequisites compose
    
    cd "$PROJECT_ROOT"
    
    if [[ "$dry_run" != "true" ]]; then
        log_info "Starting Docker Compose stack"
        
        # Use docker compose if available, fallback to docker-compose
        if docker compose version &> /dev/null; then
            docker compose up -d
        else
            docker-compose up -d
        fi
        
        if [[ "$wait_ready" == "true" ]]; then
            log_info "Waiting for services to be ready..."
            sleep 10
            
            # Check if services are healthy
            for i in {1..30}; do
                if curl -f http://localhost:8080/health/ready &> /dev/null; then
                    log_success "Services are ready"
                    break
                fi
                if [[ $i -eq 30 ]]; then
                    log_error "Services did not become ready in time"
                    exit 1
                fi
                sleep 5
            done
        fi
        
        log_success "Docker Compose stack started successfully"
        log_info "REST API: http://localhost:8080"
        log_info "gRPC API: localhost:9090"
        log_info "Metrics: http://localhost:8081/metrics"
        log_info "Prometheus: http://localhost:9091 (if monitoring profile enabled)"
        log_info "Grafana: http://localhost:3000 (if monitoring profile enabled)"
    else
        log_info "Would start Docker Compose stack"
    fi
}

# Deploy to Kubernetes
deploy_k8s() {
    local dry_run=$1
    local wait_ready=$2
    local timeout=${3:-300}
    
    check_prerequisites k8s
    
    cd "$PROJECT_ROOT"
    
    if [[ "$dry_run" != "true" ]]; then
        log_info "Deploying to Kubernetes namespace: $NAMESPACE"
        
        # Create namespace if it doesn't exist
        kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
        
        # Apply manifests
        kubectl apply -f k8s/ -n "$NAMESPACE"
        
        if [[ "$wait_ready" == "true" ]]; then
            log_info "Waiting for deployment to be ready (timeout: ${timeout}s)..."
            kubectl wait --for=condition=available --timeout="${timeout}s" deployment/go-auth-system -n "$NAMESPACE"
            
            log_success "Deployment is ready"
        fi
        
        log_success "Kubernetes deployment completed"
        
        # Show service information
        kubectl get services -n "$NAMESPACE"
        
        # Show ingress information if available
        if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
            log_info "Ingress configuration:"
            kubectl get ingress -n "$NAMESPACE"
        fi
    else
        log_info "Would deploy to Kubernetes namespace: $NAMESPACE"
        log_info "Manifests to be applied:"
        find k8s/ -name "*.yaml" -exec basename {} \;
    fi
}

# Deploy with Helm
deploy_helm() {
    local dry_run=$1
    local wait_ready=$2
    local timeout=${3:-300}
    
    check_prerequisites helm
    
    cd "$PROJECT_ROOT"
    
    local helm_args=()
    if [[ "$dry_run" == "true" ]]; then
        helm_args+=(--dry-run)
    fi
    if [[ "$wait_ready" == "true" ]]; then
        helm_args+=(--wait --timeout="${timeout}s")
    fi
    
    log_info "Deploying with Helm: $HELM_RELEASE_NAME"
    
    # Create namespace if it doesn't exist
    if [[ "$dry_run" != "true" ]]; then
        kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    fi
    
    # Install or upgrade Helm release
    helm upgrade --install "$HELM_RELEASE_NAME" \
        ./helm/go-auth-system \
        --namespace "$NAMESPACE" \
        --create-namespace \
        "${helm_args[@]}"
    
    if [[ "$dry_run" != "true" ]]; then
        log_success "Helm deployment completed"
        
        # Show release information
        helm status "$HELM_RELEASE_NAME" -n "$NAMESPACE"
    else
        log_info "Would deploy Helm release: $HELM_RELEASE_NAME in namespace: $NAMESPACE"
    fi
}

# Clean up deployments
clean_deployment() {
    local deployment_type=$1
    
    case $deployment_type in
        docker)
            log_info "Cleaning up Docker deployment"
            docker stop go-auth-system 2>/dev/null || true
            docker rm go-auth-system 2>/dev/null || true
            docker rmi "${IMAGE_NAME}:${IMAGE_TAG}" 2>/dev/null || true
            log_success "Docker cleanup completed"
            ;;
        compose)
            log_info "Cleaning up Docker Compose deployment"
            cd "$PROJECT_ROOT"
            if docker compose version &> /dev/null; then
                docker compose down -v
            else
                docker-compose down -v
            fi
            log_success "Docker Compose cleanup completed"
            ;;
        k8s)
            log_info "Cleaning up Kubernetes deployment"
            kubectl delete -f k8s/ -n "$NAMESPACE" --ignore-not-found=true
            kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
            log_success "Kubernetes cleanup completed"
            ;;
        helm)
            log_info "Cleaning up Helm deployment"
            helm uninstall "$HELM_RELEASE_NAME" -n "$NAMESPACE" 2>/dev/null || true
            kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
            log_success "Helm cleanup completed"
            ;;
        all)
            clean_deployment docker
            clean_deployment compose
            clean_deployment k8s
            clean_deployment helm
            ;;
        *)
            log_error "Unknown deployment type: $deployment_type"
            log_info "Available types: docker, compose, k8s, helm, all"
            exit 1
            ;;
    esac
}

# Run deployment tests
run_tests() {
    local test_type=$1
    
    cd "$PROJECT_ROOT"
    
    case $test_type in
        docker)
            log_info "Running Docker deployment tests"
            go test -v ./test/deployment -run TestDocker
            ;;
        k8s)
            log_info "Running Kubernetes deployment tests"
            go test -v ./test/deployment -run TestKubernetes
            ;;
        helm)
            log_info "Running Helm deployment tests"
            go test -v ./test/deployment -run TestHelm
            ;;
        all)
            log_info "Running all deployment tests"
            go test -v ./test/deployment
            ;;
        *)
            log_error "Unknown test type: $test_type"
            log_info "Available types: docker, k8s, helm, all"
            exit 1
            ;;
    esac
}

# Parse command line arguments
parse_args() {
    local command=""
    local dry_run=false
    local wait_ready=false
    local timeout=300
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            docker|compose|k8s|helm|clean|test|help)
                command=$1
                shift
                ;;
            --image-tag)
                IMAGE_TAG=$2
                shift 2
                ;;
            --namespace)
                NAMESPACE=$2
                shift 2
                ;;
            --release-name)
                HELM_RELEASE_NAME=$2
                shift 2
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --wait)
                wait_ready=true
                shift
                ;;
            --timeout)
                timeout=$2
                shift 2
                ;;
            *)
                if [[ -z "$command" ]]; then
                    log_error "Unknown command: $1"
                    show_help
                    exit 1
                else
                    # This might be a subcommand argument
                    break
                fi
                ;;
        esac
    done
    
    case $command in
        docker)
            deploy_docker "$dry_run"
            ;;
        compose)
            deploy_compose "$dry_run" "$wait_ready"
            ;;
        k8s)
            deploy_k8s "$dry_run" "$wait_ready" "$timeout"
            ;;
        helm)
            deploy_helm "$dry_run" "$wait_ready" "$timeout"
            ;;
        clean)
            if [[ $# -gt 0 ]]; then
                clean_deployment "$1"
            else
                log_error "Clean command requires deployment type"
                log_info "Usage: $0 clean [docker|compose|k8s|helm|all]"
                exit 1
            fi
            ;;
        test)
            if [[ $# -gt 0 ]]; then
                run_tests "$1"
            else
                run_tests "all"
            fi
            ;;
        help|"")
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Main execution
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi
    
    parse_args "$@"
}

main "$@"