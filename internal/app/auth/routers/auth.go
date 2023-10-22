package routers

import (
	"flag"
	"log"
	"time"

	"github.com/fatih/color"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/controllers"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/ratelimit"
)

const (
	defaultPath = "/auth"
)

// Test ratelimiting
var (
	limit ratelimit.Limiter
	rps   = flag.Int("rps", 100, "request per second")
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

// ab -n 20 -c 5 -r -s 1 -p post-data.txt http://localhost:9100/register

func Auth(config utils.Config, r *gin.Engine) {

	limit = ratelimit.New(100)

	r.Use(leakBucket())

	// Register a new user
	r.POST(defaultPath+"/register", controllers.Register(config))

	log.Printf("Current Rate Limit: %v requests/s", rps)

	// r.GET(defaultPath+"/login", controllers.Register(config))

	/*// Authenticate a user based on email/username and password.
	r.POST("user/login", controllers.Register(config))
	// Log the user out.
	r.POST("user/logout", controllers.Register(config))
	// Initiate a password reset by providing an email or username.
	r.POST("user/reset-password/request", controllers.Register(config))
	// Confirm a password reset with a reset token.
	r.POST("user/reset-password/confirm", controllers.Register(config))
	// Set up Two-Factor Authentication (2FA).
	r.POST("user/2fa/setup", controllers.Register(config))
	// Verify the 2FA code during login.
	r.POST("user/2fa/verify", controllers.Register(config))
	// Update the user's profile.
	r.PUT("user/profile", controllers.Register(config))
	// Retrieve the user's profile.
	r.GET("user/profile", controllers.Register(config))*/

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
