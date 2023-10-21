# go-auth-system

Base Structure

project-root/
├── Makefile
├── docs/
│   ├── openapi.yml
│   ├── examples/
├── cmd/
│   ├── auth-microservice/
│   │   ├── main.go
│   ├── profile-microservice/
│   │   ├── main.go
│   ├── notification-microservice/
│   │   ├── main.go
├── internal/
│   ├── app/
│   │   ├── auth/
│   │   │   ├── handlers/
│   │   │   ├── models/
│   │   │   ├── services/
│   │   ├── profile/
│   │   │   ├── handlers/
│   │   │   ├── models/
│   │   │   ├── services/
│   │   ├── notification/
│   │   │   ├── handlers/
│   │   │   ├── models/
│   │   │   ├── services/
│   ├── config/
│   ├── db/
│   ├── redis/
│   ├── api/
├── pkg/
│   ├── ...
├── migrations/
├── scripts/
├── go.mod
├── go.sum
├── Dockerfile
├── docker-compose.yaml
├── api/
│   ├── external_api_client.go



Structure for internal
project-root/
├── internal/
│   ├── app/
│   │   ├── auth/
│   │   │   ├── handlers/
│   │   │   │   ├── authentication_handlers.go
│   │   │   ├── models/
│   │   │   │   ├── user.go
│   │   │   ├── services/
│   │   │   │   ├── authentication_service.go
│   ├── profile/
│   │   ├── handlers/
│   │   │   ├── profile_handlers.go
│   │   ├── models/
│   │   │   ├── profile.go
│   │   ├── services/
│   │   │   ├── profile_service.go
│   ├── notification/
│   │   ├── handlers/
│   │   │   ├── notification_handlers.go
│   │   ├── models/
│   │   │   ├── notification.go
│   │   ├── services/
│   │   │   ├── notification_service.go
│   ├── config/
│   │   ├── app_config.go
│   ├── db/
│   │   ├── migrations/
│   │   │   ├── migration_files.go
│   │   ├── models/
│   │   │   ├── shared_models.go
│   ├── redis/
│   │   ├── redis_client.go
│   ├── api/
│   │   ├── external_api_client.go
│   │   ├── ...
