package cache

import (
	"context"

	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

type PostCache interface {
	GetPost(ctx context.Context, key string) *sqlc.Post
	SetPost(ctx context.Context, key string, value *sqlc.Post)
}
