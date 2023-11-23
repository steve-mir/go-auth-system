package main

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	// "github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/steve-mir/go-auth-system/gapi"
	"github.com/steve-mir/go-auth-system/internal/app/auth/routers"
	profiles "github.com/steve-mir/go-auth-system/internal/app/profiles/routers"
	security "github.com/steve-mir/go-auth-system/internal/app/security/routers"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/steve-mir/go-auth-system/pb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	// l := log.New(os.Stdout, "product-api", log.LstdFlags)
	l, _ := zap.NewProduction()

	// Use Viper for configuration management
	config, err := utils.LoadConfig(".")
	if err != nil {
		l.Fatal("cannot load config", zap.Error(err))
	}

	if config.Environment == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	// Run db migrations
	runDbMigration(config.MigrationUrl, config.DBSource)

	// Create the routes
	db, err := sqlc.CreateDbPool(config)
	if err != nil {
		l.Error("cannot create db pool", zap.Error(err))
		return
	}

	// Serve your Swagger documentation if needed
	// r.StaticFile("/swagger.yaml", "./swagger.yaml")

	//**************** GRPC Server **********************/
	go runGrpcGatewayServer(db, config, l)
	runGrpcServer(db, config, l)

	//**************** GIN Server***********************/
	// srv := createGinServer(db, config, l)

	// // ? OLD
	// go func() {
	// 	if err := srv.ListenAndServe(); err != nil {
	// 		l.Error("Server error", zap.Error(err))
	// 	}
	// }()

	// // Graceful shutdown handling
	// sigChan := make(chan os.Signal, 1)
	// signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM) // os.Interrupt
	// sig := <-sigChan
	// l.Info("Received terminate, graceful shutdown", zap.String("signal", sig.String()))
	// defer db.Close() // close db connection

	// // Graceful shutdown with error handling
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()
	// if err := srv.Shutdown(ctx); err != nil {
	// 	l.Error("Graceful shutdown error", zap.Error(err))
	// }

}

func runDbMigration(migrationUrl string, dbSource string) {
	migration, err := migrate.New(migrationUrl, dbSource)
	if err != nil {
		log.Fatal().Msg("cannot create new migration instance:") //, err)
	}

	if err = migration.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatal().Msg("failed to run migrate up:") //, err)
	}
	log.Info().Msg("db migrated successfully")

}

func runGrpcServer(db *sql.DB, config utils.Config, l *zap.Logger) {
	server, err := gapi.NewServer(db, config, l)
	if err != nil {
		log.Fatal().Msg("cannot create a server:") //, err)
	}

	grpcLogger := grpc.UnaryInterceptor(gapi.GrpcLogger)
	grpcServer := grpc.NewServer(grpcLogger)
	pb.RegisterUserAuthServer(grpcServer, server)
	reflection.Register(grpcServer)

	listener, err := net.Listen("tcp", config.GRPCServerAddress)
	if err != nil {
		log.Fatal().Msg("cannot create listener:") //, err)
	}

	log.Info().Msgf("start grpc server at %s", listener.Addr().String())
	err = grpcServer.Serve(listener)
	if err != nil {
		log.Fatal().Msg("cannot start grpc server")
	}
}

func runGrpcGatewayServer(db *sql.DB, config utils.Config, l *zap.Logger) {
	server, err := gapi.NewServer(db, config, l)
	if err != nil {
		log.Fatal().Msg("cannot create a server:") //, err)
	}

	jsonOptions := runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			UseProtoNames: true,
		},
		UnmarshalOptions: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	})

	grpcMux := runtime.NewServeMux(jsonOptions)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = pb.RegisterUserAuthHandlerServer(ctx, grpcMux, server)
	if err != nil {
		log.Fatal().Msg("cannot register handler server")
	}

	mux := http.NewServeMux()
	mux.Handle("/", grpcMux)

	listener, err := net.Listen("tcp", config.HTTPServerAddress)
	if err != nil {
		log.Fatal().Msg("cannot create listener:") //, err)
	}

	log.Info().Msgf("start HTTP gateway server at %s", listener.Addr().String())
	err = http.Serve(listener, mux)
	if err != nil {
		log.Fatal().Msg("cannot start HTTP Gateway server")
	}
}

func createGinServer(db *sql.DB, config utils.Config, l *zap.Logger) *http.Server {
	port := config.HTTPServerAddress
	router := gin.New()

	setupRouter(db, config, router, l)

	return &http.Server{
		Addr:         port, //":" + port,
		Handler:      router,
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}
}

func setupRouter(db *sql.DB, config utils.Config, route *gin.Engine, l *zap.Logger) {
	// Create db store and pass as injector
	store := sqlc.NewStore(db)
	// Create cors
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"https://localhost:3000"}
	route.Use(cors.New(corsConfig))

	// Use structured logger middleware
	route.Use(gin.Logger())
	routers.Auth(config, db, store, l, route)
	security.Security(config, db, store, l, route)
	profiles.Profile(config, store, l, route)
}
