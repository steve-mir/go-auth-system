package token

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/o1egl/paseto"
	"golang.org/x/crypto/pbkdf2"
)

const minSecretKeySize = 32

type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte

	// ? Caching
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
func (maker *PasetoMaker) CreateToken(payloadData PayloadData, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(payloadData, duration)

	if err != nil {
		return "", &Payload{}, err
	}

	accessToken, err := maker.paseto.Encrypt(maker.symmetricKey, payload, nil)
	return accessToken, payload, err
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

	// Check for expiry if is refresh token
	err = payload.ValidateExpiry()
	if err != nil {
		return payload, err
	}

	// Cache validated token
	maker.validTokens[token] = struct{}{}

	return payload, nil
}

// Add a revoke endpoint
// todo: implement
func (m *PasetoMaker) RevokeToken(token string) error {
	// Used for logout
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
