package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

type redisCache struct {
	host    string
	db      int
	expires time.Duration
}

func NewRedisCache(host string, db int, expires time.Duration) PostCache {
	return &redisCache{
		host:    host,
		db:      db,
		expires: expires,
	}
}

func (cache *redisCache) getClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr: "0.0.0.0:6379",
		// Addr:     cache.host,
		// Password: "",
		// DB:       cache.db,
	})
}

func (uc *redisCache) GetPost(ctx context.Context, key string) *sqlc.Post {
	client := uc.getClient()

	val, err := client.Get(ctx, key).Result()
	if err != nil {
		return nil
	}

	post := &sqlc.Post{}

	err = json.Unmarshal([]byte(val), post)
	if err != nil {
		panic(err)
	}
	return post
}

func (uc *redisCache) SetPost(ctx context.Context, key string, value *sqlc.Post) {
	client := uc.getClient()

	postJson, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	err = client.Set(ctx, key, postJson, uc.expires*time.Second).Err()
	if err != nil {
		panic(err)
	}
}
