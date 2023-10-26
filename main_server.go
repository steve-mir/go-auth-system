package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/routers"
	profiles "github.com/steve-mir/go-auth-system/internal/app/profiles/routers"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

func main() {
	// l := log.New(os.Stdout, "product-api", log.LstdFlags)
	l, _ := zap.NewProduction()

	// Use Viper for configuration management
	config, err := utils.LoadConfig(".")
	if err != nil {
		l.Fatal("cannot load config", zap.Error(err))
	}

	port := config.ServerAddress

	router := gin.New()

	// Create the routes
	db, err := sqlc.CreateDbPool(config)
	if err != nil {
		l.Error("cannot create db pool", zap.Error(err))
		return
	}
	setupRouter(db, config, router, l)

	// Serve your Swagger documentation if needed
	// r.StaticFile("/swagger.yaml", "./swagger.yaml")

	srv := &http.Server{
		Addr:         port, //":" + port,
		Handler:      router,
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			l.Error("Server error", zap.Error(err))
		}
	}()

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	// signal.Notify(sigChan, os.Kill)
	sig := <-sigChan
	l.Info("Received terminate, graceful shutdown", zap.String("signal", sig.String()))
	defer db.Close() // close db connection

	// Graceful shutdown with error handling
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		l.Error("Graceful shutdown error", zap.Error(err))
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
	routers.Auth(config, store, l, route)
	profiles.Profile(config, store, l, route)
}
