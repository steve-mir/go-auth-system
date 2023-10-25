package token

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

// User ID - The unique identifier of the logged in user. This allows fetching the user's attributes like roles/permissions from the database for authorization.
// Session ID - The id of the user's session in the sessions table. Used to validate the session is valid on each request.
// Issued at timestamp - When the token was issued. Used to calculate expiry.
// Expiry timestamp - When the token expires.

// Not before timestamp - Earliest time the token can be used (optional).
// Issuer - Your service's ID, e.g. https://myapp.com.
// Audience - Intended API audience, e.g. https://myapp.com/api.
// IP Address - The IP address of the client issued to. Can be used to detect suspicious usage.
// User agent - The user agent string of the client. Can be used to identify clients.

type PayloadData struct {
	// Role     string    `json:"role"`
	RefreshID      string      `json:"refresh_token"`
	UserId         uuid.UUID   `json:"user_id"`
	IsRefresh      bool        `json:"is_refresh"`
	Username       string      `json:"username"`
	IsUserVerified bool        `json:"is_user_verified"` // End of user part
	SessionID      uuid.UUID   `json:"session_id"`
	Issuer         string      `json:"issuer"`
	Audience       string      `json:"audience"`
	IP             pqtype.Inet `json:"ip"`
	UserAgent      string      `json:"user_agent"`
}

type Payload struct {
	PayloadData

	// ID           uuid.UUID `json:"id"` // Used in refresh token to identify the session. Serves as session Id too
	RefreshAfter time.Time `json:"not_before"`
	Expires      time.Time `json:"expires"`
	IssuedAt     time.Time `json:"issued_at"`
}

// type CustomPayload struct {
// 	Payload
// 	User sqlc.User
// }

func NewPayload(payload PayloadData, duration time.Duration) (*Payload, error) {
	// tokenID, err := uuid.NewRandom()
	// if err != nil {
	// 	return nil, err
	// }

	return &Payload{
		PayloadData: payload,
		// ID:           tokenID,
		Expires:      time.Now().Add(duration),
		RefreshAfter: time.Now().Add(duration), // TODO: Fix refresh after
		IssuedAt:     time.Now(),
	}, nil

}

// func CustomNewPayload(user Payload, duration time.Duration) (*Payload, error) {
// 	payload, err := NewPayload(user, duration)
// 	if err != nil {
// 		return nil, err
// 	}

// 	customPayload := &Payload{
// 		// Payload: user,
// 	}

// 	return customPayload, nil
// }

// func (payload *Payload) Valid() error {
// 	if time.Now().After(payload.Expires) {
// 		return ErrExpiredToken
// 	}
// 	return nil
// }

func (payload *Payload) ValidateExpiry() error {
	currentTime := time.Now()
	if currentTime.After(payload.Expires) {
		return ErrExpiredToken
	}
	return nil
}
