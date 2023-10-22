package token

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/o1egl/paseto"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"golang.org/x/crypto/pbkdf2"
)

const minSecretKeySize = 32

type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte

	// ? TODO Caching
	validTokens map[string]struct{} // TODO: Cache with Redis or DynamoDB distributed cache
}

func NewPasetoMaker(symmetricKey string) (Maker, error) {
	if len(symmetricKey) < minSecretKeySize {
		return nil, fmt.Errorf("invalid key size: must be at least %d bytes", minSecretKeySize)
	}

	// Key derivation
	key := pbkdf2.Key([]byte(symmetricKey), []byte("paseto-key"), 10000, minSecretKeySize, sha256.New)

	maker := &PasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: key,

		// Caching
		validTokens: make(map[string]struct{}),
	}

	return maker, nil

}

// CreateToken implements Maker.
func (maker *PasetoMaker) CreateToken(username string, duration time.Duration) (string, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", err
	}
	// Allow custom expiry
	// payload.Expires = time.Now().Add(expiry)

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
	// Check cache first
	if _, ok := maker.validTokens[token]; ok {
		return nil, ErrInvalidToken
	}

	payload := &Payload{}

	err := maker.paseto.Decrypt(token, maker.symmetricKey, payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}

	// Cache validated token
	maker.validTokens[token] = struct{}{}

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

// Add a revoke endpoint
func (m *PasetoMaker) RevokeToken(token string) error {
	delete(m.validTokens, token)
	return nil
}

// TODO: Add telemetry

// package stats

// func RecordTokenIssued() {
//   // record token issued metrics
// }

// func RecordTokenInvalid() {
//   // record invalid token metrics
// }

// stats.RecordTokenIssued()
// stats.RecordTokenInvalid()
