package token

import (
	"time"
)

type Maker interface {
	// CreateToken creates a new token for a specific username and duration
	CreateToken(payloadData PayloadData, duration time.Duration) (string, *Payload, error)

	// VerifyToken checks if the token is valid or not
	VerifyToken(token string) (*Payload, error)

	// Add a revoke endpoint
	RevokeToken(token string) error
}
