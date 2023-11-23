package gapi

import (
	"database/sql"
	"fmt"

	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/steve-mir/go-auth-system/pb"
	"github.com/steve-mir/go-auth-system/worker"
	"go.uber.org/zap"
)

type Server struct {
	pb.UnimplementedUserAuthServer
	config          utils.Config
	store           *sqlc.Store
	l               *zap.Logger
	db              *sql.DB
	tokenMaker      token.Maker
	taskDistributor worker.TaskDistributor
}

// GRPC server
func NewServer(db *sql.DB, config utils.Config, taskDistributor worker.TaskDistributor, l *zap.Logger) (*Server, error) {
	tokenMaker, err := token.NewPasetoMaker(config.AccessTokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %w", err)
	}
	// Create db store and pass as injector
	return &Server{
		config:          config,
		db:              db,
		store:           sqlc.NewStore(db),
		l:               l,
		tokenMaker:      tokenMaker,
		taskDistributor: taskDistributor,
	}, nil
}
