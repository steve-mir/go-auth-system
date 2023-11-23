package worker

import (
	"context"

	"github.com/hibiken/asynq"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

type TaskProcessor interface {
	Start() error
	ProcessTaskSendVerifyEmail(ctx context.Context, task *asynq.Task) error
}

type RedisTaskProcessor struct {
	server *asynq.Server
	store  sqlc.Store
}

func NewRedisTaskProcessor(redisOpt asynq.RedisClientOpt, store sqlc.Store) TaskProcessor {

	server := asynq.NewServer(redisOpt, asynq.Config{})

	return &RedisTaskProcessor{
		server: server,
		store:  store,
	}
}

func (processor *RedisTaskProcessor) Start() error {
	mux := asynq.NewServeMux()

	// Register tasks here. Very important
	mux.HandleFunc(TaskSendVerifyEmail, processor.ProcessTaskSendVerifyEmail)

	return processor.server.Start(mux)
}
