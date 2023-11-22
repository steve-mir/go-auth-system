package gapi

import (
	"database/sql"

	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/steve-mir/go-auth-system/pb"
	"go.uber.org/zap"
)

type Server struct {
	pb.UnimplementedUserAuthServer
	config utils.Config
	store  *sqlc.Store
	l      *zap.Logger
	// db *sql.DB
}

// GRPC server
func NewServer(db *sql.DB, config utils.Config, l *zap.Logger) (*Server, error) {
	// Create db store and pass as injector
	return &Server{
		config: config,
		store:  sqlc.NewStore(db),
		l:      l,
	}, nil
}
