package token

import (
	"time"

	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

type Maker interface {
	// CreateToken creates a new token for a specific username and duration
	CreateToken(username string, duration time.Duration) (string, error)

	// CreateCustomToken creates a new token for a specific username and duration
	CreateCustomToken(user sqlc.User, duration time.Duration) (string, *CustomPayload, error)

	// VerifyToken checks if the token is valid or not
	VerifyToken(token string) (*Payload, error)

	// VerifyCustomToken checks if the token is valid or not
	VerifyCustomToken(token string) (*CustomPayload, error)
}
