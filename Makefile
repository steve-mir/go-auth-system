# docker run --name postgres16 -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=toor -d postgres:16.0-alpine3.18
environ:
	export PATH="$PATH:$(go env GOPATH)/bin"
air_init:
	air init

air_run:
	air

start_ps:
	docker start postgres16

start_redis:
	docker start redis

postgres:
	docker run --name postgres16 -p 5434:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=toor -d postgres:16.0-alpine3.18

redis:
	docker run --name redis -p 6379:6379 -d redis:7.0-alpine

createdb:
	docker exec -it postgres16 createdb --username=root --owner=root auth_system

dropdb:
	docker exec -it postgres16 dropdb auth_system

migrate_init:
	migrate create -ext sql -dir sql/migrations -seq init_schema

migrateup:
	migrate -path sql/migrations -database "postgresql://root:toor@localhost:5434/auth_system?sslmode=disable" -verbose up

migrateup1:
	migrate -path sql/migrations -database "postgresql://root:toor@localhost:5434/auth_system?sslmode=disable" -verbose up 1

migratedown:
	migrate -path sql/migrations -database "postgresql://root:toor@localhost:5434/auth_system?sslmode=disable" -verbose down

migratedown1:
	migrate -path sql/migrations -database "postgresql://root:toor@localhost:5434/auth_system?sslmode=disable" -verbose down 1

sqlc_init:
	sqlc init

sqlc:
	sqlc generate

test:
	go test -v -cover ./...

build:
	go build -o bin/go-auth-system ./cmd/server

run:
	go run ./cmd/server

run-config:
	go run ./cmd/server -config=config.example.yaml

tidy:
	go mod tidy

clean:
	rm -rf bin/

# Development helpers
dev-setup: postgres redis createdb
	@echo "Development environment setup complete"

dev-start: start_ps start_redis
	@echo "Development services started"

dev-stop:
	docker stop postgres16 redis || true

dev-clean: dev-stop
	docker rm postgres16 redis || true

# Configuration validation
validate-config:
	go run ./cmd/server -config=config.example.yaml --validate-only

proto:
	rm -f pb/*.go
	rm -f docs/swagger/*.swagger.json
	protoc --proto_path=protos --go_out=pb --go_opt=paths=source_relative \
	--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
	--grpc-gateway_out=pb --grpc-gateway_opt=paths=source_relative \
	--openapiv2_out=docs/swagger --openapiv2_opt=allow_merge=true,merge_file_name=auth_system \
	protos/*.proto

evans:
	evans --host localhost --port 9901 -r repl

.PHONY: postgres createdb dropdb migrateup migrateup1 migratedown migratedown1 sqlc test run environ air_init air_run start_redis redis start_ps dev-setup dev-start dev-stop dev-clean validate-config

# migrate create -ext sql -dir db/migration -seq add_user_session

# instal swagger
# brew tap go-swagger/go-swagger
# brew install go-swagger
# goswagger.io