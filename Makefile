# Go Auth System Makefile

# Variables
BINARY_NAME=go-auth-system
MAIN_PATH=./cmd/server
MIGRATE_PATH=./cmd/migrate

# Build commands
.PHONY: build
build:
	go build -o bin/$(BINARY_NAME) $(MAIN_PATH)

.PHONY: build-migrate
build-migrate:
	go build -o bin/migrate $(MIGRATE_PATH)

.PHONY: run
run:
	go run $(MAIN_PATH)

.PHONY: run-config
run-config:
	go run $(MAIN_PATH) -config=config.yaml

# Database commands
.PHONY: migrate-up
migrate-up: build-migrate
	./bin/migrate -command=up

.PHONY: migrate-down
migrate-down: build-migrate
	./bin/migrate -command=down

.PHONY: migrate-status
migrate-status: build-migrate
	./bin/migrate -command=status

# Code generation
.PHONY: sqlc
sqlc:
	sqlc generate

.PHONY: proto
proto:
	rm -f pb/*.go
	rm -f docs/swagger/*.swagger.json
	protoc --proto_path=proto --go_out=pb --go_opt=paths=source_relative \
	--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
	--grpc-gateway_out=pb --grpc-gateway_opt=paths=source_relative \
	--openapiv2_out=docs/swagger --openapiv2_opt=allow_merge=true,merge_file_name=go-auth-system \
	proto/*.proto


# Testing
.PHONY: test
test:
	go test -v ./...

.PHONY: test-coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: test-integration
test-integration:
	go run -tags=integration test_integration.go

# Docker commands
.PHONY: docker-build
docker-build:
	docker build -t $(BINARY_NAME):latest .

.PHONY: docker-up
docker-up:
	docker-compose up -d

.PHONY: docker-down
docker-down:
	docker-compose down

.PHONY: docker-logs
docker-logs:
	docker-compose logs -f

# Deployment commands
.PHONY: deploy-docker
deploy-docker: docker-build
	bash scripts/deploy.sh docker

.PHONY: deploy-compose
deploy-compose:
	bash scripts/deploy.sh compose --wait

.PHONY: deploy-k8s
deploy-k8s:
	bash scripts/deploy.sh k8s --wait

.PHONY: deploy-helm
deploy-helm:
	bash scripts/deploy.sh helm --wait

.PHONY: clean-deployments
clean-deployments:
	bash scripts/deploy.sh clean all

.PHONY: test-deployment
test-deployment:
	go test -v ./test/deployment

.PHONY: validate-k8s
validate-k8s:
	kubectl apply --dry-run=client -f k8s/

.PHONY: validate-helm
validate-helm:
	helm template go-auth-system ./helm/go-auth-system > /dev/null

# Development helpers
.PHONY: postgres
postgres:
	docker run --name postgres-auth -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=auth_system -p 5432:5432 -d postgres:16-alpine

.PHONY: redis
redis:
	docker run --name redis-auth -p 6379:6379 -d redis:7-alpine

.PHONY: clean
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html
	docker-compose down --volumes --remove-orphans

# Health check test
.PHONY: health-check
health-check:
	@echo "Testing health endpoints..."
	@curl -s http://localhost:8080/health | jq . || echo "Health endpoint not available"
	@curl -s http://localhost:8080/health/live | jq . || echo "Liveness endpoint not available"
	@curl -s http://localhost:8080/health/ready | jq . || echo "Readiness endpoint not available"

# Help
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  build          - Build the main application"
	@echo "  build-migrate  - Build the migration tool"
	@echo "  run            - Run the application"
	@echo "  run-config     - Run with config file"
	@echo "  migrate-up     - Run database migrations"
	@echo "  migrate-down   - Rollback database migrations"
	@echo "  migrate-status - Show migration status"
	@echo "  sqlc           - Generate SQLC code"
	@echo "  proto          - Generate protobuf code"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  test-integration - Run integration tests"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-up      - Start with Docker Compose"
	@echo "  docker-down    - Stop Docker Compose"
	@echo "  deploy-docker  - Deploy with Docker"
	@echo "  deploy-compose - Deploy with Docker Compose"
	@echo "  deploy-k8s     - Deploy to Kubernetes"
	@echo "  deploy-helm    - Deploy with Helm"
	@echo "  clean-deployments - Clean all deployments"
	@echo "  test-deployment - Run deployment tests"
	@echo "  validate-k8s   - Validate Kubernetes manifests"
	@echo "  validate-helm  - Validate Helm chart"
	@echo "  postgres       - Start PostgreSQL container"
	@echo "  redis          - Start Redis container"
	@echo "  health-check   - Test health endpoints"
	@echo "  clean          - Clean build artifacts"
	@echo "  help           - Show this help"