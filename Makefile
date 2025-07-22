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
	@echo "  postgres       - Start PostgreSQL container"
	@echo "  redis          - Start Redis container"
	@echo "  health-check   - Test health endpoints"
	@echo "  clean          - Clean build artifacts"
	@echo "  help           - Show this help"