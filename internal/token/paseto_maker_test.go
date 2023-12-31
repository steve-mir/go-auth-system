package token

import (
	"testing"
	"time"

	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestPasetoMaker(t *testing.T) {

	maker, err := NewPasetoMaker(utils.RandomString(32))
	require.NoError(t, err)

	username := utils.RandomEmail()
	duration := time.Minute

	issuedAt := time.Now()
	expiredAt := issuedAt.Add(duration)

	token, _, err := maker.CreateToken(PayloadData{}, duration) //maker.CreateToken(username, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err := maker.VerifyToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	require.NotZero(t, payload.SessionID)
	require.Equal(t, username, payload.Username)
	require.WithinDuration(t, issuedAt, payload.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, payload.Expires, time.Second)
}

func TestExpiredPasetoToken(t *testing.T) {
	// symmetricKey, _ := utils.GenerateRandomKey(minSecretKeySize)
	maker, err := NewPasetoMaker(utils.RandomString(32))
	require.NoError(t, err)

	token, _, err := maker.CreateToken(PayloadData{}, -time.Minute) //maker.CreateToken(utils.RandomEmail(), -time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err := maker.VerifyToken(token)
	require.Error(t, err)
	require.EqualError(t, err, ErrExpiredToken.Error())
	require.Nil(t, payload)
}
