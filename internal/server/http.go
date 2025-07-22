package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/health"
)

// HTTPServer represents the HTTP server
type HTTPServer struct {
	server    *http.Server
	healthSvc *health.Service
	config    *config.ServerConfig
}

// NewHTTPServer creates a new HTTP server
func NewHTTPServer(cfg *config.ServerConfig, healthSvc *health.Service) *HTTPServer {
	mux := http.NewServeMux()

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	httpServer := &HTTPServer{
		server:    server,
		healthSvc: healthSvc,
		config:    cfg,
	}

	// Setup routes
	httpServer.setupRoutes(mux)

	return httpServer
}

// setupRoutes configures the HTTP routes
func (s *HTTPServer) setupRoutes(mux *http.ServeMux) {
	// Health check endpoints
	mux.HandleFunc("/health", s.healthSvc.Handler())
	mux.HandleFunc("/health/live", s.livenessHandler())
	mux.HandleFunc("/health/ready", s.readinessHandler())

	// Basic info endpoint
	mux.HandleFunc("/", s.rootHandler())

	// TODO: Add API routes here
	// mux.HandleFunc("/api/v1/", s.apiHandler())
}

// Start starts the HTTP server
func (s *HTTPServer) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("HTTP server starting on %s\n", s.server.Addr)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server failed: %w", err)
	}

	return nil
}

// Stop stops the HTTP server
func (s *HTTPServer) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// rootHandler handles requests to the root path
func (s *HTTPServer) rootHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"service": "go-auth-system",
			"version": "1.0.0",
			"status": "running",
			"endpoints": {
				"health": "/health",
				"liveness": "/health/live", 
				"readiness": "/health/ready"
			}
		}`)
	}
}

// livenessHandler handles liveness probe requests
func (s *HTTPServer) livenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"status": "alive",
			"timestamp": "%s"
		}`, time.Now().Format(time.RFC3339))
	}
}

// readinessHandler handles readiness probe requests
func (s *HTTPServer) readinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Check if all critical components are ready
		healthCheck := s.healthSvc.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		if healthCheck.Status == health.StatusHealthy {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
				"status": "ready",
				"timestamp": "%s"
			}`, time.Now().Format(time.RFC3339))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{
				"status": "not_ready",
				"timestamp": "%s",
				"reason": "One or more components are unhealthy"
			}`, time.Now().Format(time.RFC3339))
		}
	}
}
