package security

import (
	"database/sql"
	"flag"
	"log"
	"time"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	controllers "github.com/steve-mir/go-auth-system/internal/app/security/controllers"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/ratelimit"
	"go.uber.org/zap"
)

const (
	defaultPath = "/security"
)

// Test ratelimiting
var (
	limit  ratelimit.Limiter
	secRps = flag.Int("rps", 100, "request per second")
)

func leakBucket() gin.HandlerFunc {
	prev := time.Now()
	return func(ctx *gin.Context) {
		now := limit.Take()
		log.Print(now.Sub(prev))
		log.Print(color.CyanString("%v", now.Sub(prev)))
		prev = now
	}
}

func Security(config utils.Config, db *sql.DB, store *sqlc.Store, l *zap.Logger, r *gin.Engine) {

	limit = ratelimit.New(100)

	r.Use(leakBucket())
	log.Printf("Current Rate Limit: %v requests/s", secRps)

	// Public routes
	// Requires throttling (rate limiting). No auth header required
	// TODO: Implement throttling to prevent brute force attacks (rate limiting)
	public := r.Group(defaultPath)
	public.POST("/password-reset", controllers.ResetUserPwdRequest(config, store, l)) // Request password reset
	public.POST("/password-reset/new", controllers.ResetPwd(config, store, l))        // Change password

	// Private routes
	// Protected routes with auth header required
	// private := r.Group(defaultPath)
	// private.Use(middlewares.AuthMiddlerWare(config, l))
	// private.Use(middlewares.Verify(config, store, l))
	// private.GET("/logout", controllers.Logout(config, store, l))

}

/*
import (
	"flag"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/controllers"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

const (
	defaultPath = "/auth"
)

// Token bucket struct
type bucket struct {
	rate     float64   // rate (requests/second)
	capacity int64     // max burst
	tokens   float64   // available tokens
	last     time.Time // last request time
}

// Initialize and load state from redis

//   Load bucket from redis

// Save bucket to redis

// Take token from bucket
func (b *bucket) takeToken() bool {
	// Token bucket algo logic

	return true //allowed
}

// Test ratelimiting
var (
	// Track the last request time for each IP
	ipRequestTimes      = make(map[string]time.Time)
	ipRequestTimesMutex sync.Mutex

	rps = flag.Int("rps", 10, "requests per second")
)

func leakBucket() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get the client's IP address
		clientIP := ctx.ClientIP()

		// Lock the mutex to protect the IP tracking map
		ipRequestTimesMutex.Lock()
		lastRequestTime, exists := ipRequestTimes[clientIP]
		ipRequestTimesMutex.Unlock()

		now := time.Now()

		// Check if the last request time exists and is within the allowed rate
		if exists && now.Sub(lastRequestTime) < time.Second/time.Duration(*rps) {
			// Rate limit exceeded, return an error response
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				"message": "Rate limit exceeded",
			})
			ctx.Abort()
			return
		}

		// Update the last request time for this IP
		ipRequestTimesMutex.Lock()
		ipRequestTimes[clientIP] = now
		ipRequestTimesMutex.Unlock()

		// Continue processing the request
		ctx.Next()
	}
}

func Auth(config utils.Config, r *gin.Engine) {
	// limit = ratelimit.New(100)

	r.Use(leakBucket())
	// Register a new user
	r.POST(defaultPath+"/register", controllers.Register(config))

	// Register a new user
	r.GET(defaultPath+"/login", controllers.Register(config))

	log.Printf("Current Rate Limit: %v requests/s", *rps)
}
*/
