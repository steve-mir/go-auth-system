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
	docker exec -it postgres16 createdb --username=root --owner=root go_auth_system

dropdb:
	docker exec -it postgres16 dropdb go_auth_system

migrate_init:
	migrate create -ext sql -dir internal/db/migration -seq users

migrateup:
	migrate -path internal/db/migration -database "postgresql://root:toor@localhost:5433/go_auth_system?sslmode=disable" -verbose up

migrateup1:
	migrate -path internal/db/migration -database "postgresql://root:toor@localhost:5433/go_auth_system?sslmode=disable" -verbose up 1

migratedown:
	migrate -path internal/db/migration -database "postgresql://root:toor@localhost:5433/go_auth_system?sslmode=disable" -verbose down

migratedown1:
	migrate -path internal/db/migration -database "postgresql://root:toor@localhost:5433/go_auth_system?sslmode=disable" -verbose down 1

sqlc_init:
	sqlc init

sqlc:
	sqlc generate

test:
	go test -v -cover ./...

run:
	go run main.go

proto:
	rm -f pb/*.go
	protoc --proto_path=protos --go_out=pb --go_opt=paths=source_relative \
	--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
	protos/*.proto

evans:
	evans --host localhost --port 9901 -r repl

.PHONY: postgres createdb dropdb migrateup migrateup1 migratedown migratedown1 sqlc test run environ air_init air_run start_redis redis start_ps

# migrate create -ext sql -dir db/migration -seq add_user_session

# instal swagger
# brew tap go-swagger/go-swagger
# brew install go-swagger
# goswagger.io