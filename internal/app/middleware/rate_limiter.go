package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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
