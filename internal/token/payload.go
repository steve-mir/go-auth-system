package token

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

type Payload struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Expires  time.Time `json:"expires"`
	IssuedAt time.Time `json:"issued_at"`
}

type CustomPayload struct {
	Payload
	User sqlc.User
}

func NewPayload(username string, duration time.Duration) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	return &Payload{
		ID:       tokenID,
		Username: username,
		Expires:  time.Now().Add(duration),
		IssuedAt: time.Now(),
	}, nil
}

func CustomNewPayload(user sqlc.User, duration time.Duration) (*CustomPayload, error) {
	payload, err := NewPayload(user.Email.String, duration)
	if err != nil {
		return nil, err
	}

	customPayload := &CustomPayload{
		Payload: *payload,
		User:    user,
	}

	return customPayload, nil
}

func (payload *Payload) Valid() error {
	if time.Now().After(payload.Expires) {
		return ErrExpiredToken
	}
	return nil
}
