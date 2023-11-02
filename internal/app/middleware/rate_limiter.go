package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type Bucket struct {
	rate     float64
	capacity int
	tokens   float64
	last     time.Time
}

func NewBucket(rate float64, capacity int) *Bucket {
	return &Bucket{
		rate:     rate,
		capacity: capacity,
		tokens:   float64(capacity),
		last:     time.Now(),
	}
}

func (b *Bucket) TakeToken() bool {
	current := time.Now()
	timePassed := current.Sub(b.last)
	tokensAdded := timePassed.Seconds() * b.rate

	b.tokens += tokensAdded
	if b.tokens > float64(b.capacity) {
		b.tokens = float64(b.capacity)
	}
	b.last = current

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func Throttler(rate float64, capacity int) gin.HandlerFunc {
	bucket := NewBucket(rate, capacity)

	return func(c *gin.Context) {
		if !bucket.TakeToken() {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		c.Next()
	}
}

// ! GPT rate limiting

func RateLimitMiddleware2(limiter *rate.Limiter) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if limiter.Allow() {
			// The request is allowed; continue processing
			ctx.Next()
		} else {
			// The request exceeds the rate limit; return an error response
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				"message": "Rate limit exceeded",
			})
			ctx.Abort()
		}
	}
}

/***************************************************************************************/
// ? Youtube rate limiting
// func RateLimit2() gin.HandlerFunc {
// 	limit := rate.NewLimiter(2, 4) // 2 request per sec with max of 4 from client
// 	return func(ctx *gin.Context) {
// 		if !limit.Allow() {
// 			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Exceeded limit"})
// 			return
// 		}
// 		ctx.Next()
// 	}
// }

// test in terminal: for i in {1..6}; do curl http://localhost:9100/security/password-reset/pwd; done
// for i in {1..11}; do curl http://localhost:9100/security/password-reset/pwd sleep 1 done
func RateLimit(rps int, burst int) gin.HandlerFunc {
	// Create a client type
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}

	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
	)

	// launch background routine to remove old entries every 1 minute from map
	go func() {
		for {
			time.Sleep(time.Minute)
			// Lock before staring to cleanup
			mu.Lock()
			for ip, client := range clients {
				if time.Since(client.lastSeen) > 3*time.Minute {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(ctx *gin.Context) {
		// Get ip of client
		ip := ctx.ClientIP()

		// Lock()
		mu.Lock()
		// Check if the ip is in the map
		if _, found := clients[ip]; !found {
			clients[ip] = &client{limiter: rate.NewLimiter(
				rate.Limit(rps),
				burst,
			)}
		}

		// Update last seen of client
		clients[ip].lastSeen = time.Now()

		// Check if request allowed
		if !clients[ip].limiter.Allow() {
			mu.Unlock()
			ctx.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Exceeded limit"})
			return
		}
		mu.Unlock()
		ctx.Next()
	}
}
