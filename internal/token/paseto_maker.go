package token

import (
	"fmt"
	"time"

	"github.com/o1egl/paseto"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

const minSecretKeySize = 32

type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}

func NewPasetoMaker(symmetricKey string) (Maker, error) {
	if len(symmetricKey) < minSecretKeySize {
		return nil, fmt.Errorf("invalid key size: must be at least %d characters", minSecretKeySize)
	}

	return &PasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
	}, nil
}

// CreateToken implements Maker.
func (maker *PasetoMaker) CreateToken(username string, duration time.Duration) (string, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", err
	}
	return maker.paseto.Encrypt(maker.symmetricKey, payload, nil)
}

// CreateCustomToken implements Maker.
func (maker *PasetoMaker) CreateCustomToken(user sqlc.User, duration time.Duration) (string, *CustomPayload, error) {
	payload, err := CustomNewPayload(user, duration)
	if err != nil {
		return "", payload, err
	}
	pToken, err := maker.paseto.Encrypt(maker.symmetricKey, payload, nil)
	return pToken, payload, err
}

// VerifyToken implements Maker.
func (maker *PasetoMaker) VerifyToken(token string) (*Payload, error) {
	payload := &Payload{}

	err := maker.paseto.Decrypt(token, maker.symmetricKey, payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// VerifyToken implements Maker.
func (maker *PasetoMaker) VerifyCustomToken(token string) (*CustomPayload, error) {
	payload := &CustomPayload{}

	err := maker.paseto.Decrypt(token, maker.symmetricKey, payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}

	return payload, nil
}
