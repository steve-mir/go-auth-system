package services

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq" // Import the PostgreSQL driver
	_ "github.com/sqlc-dev/pqtype"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

type user struct {
	ID                int64     `json:"id"`
	Email             string    `json:"email"`
	PasswordChangedAt time.Time `json:"password_changed_at"`
	LastLogin         time.Time `json:"last_login"`
	CreatedAt         time.Time `json:"created_at"`
}

func newUserResp(user sqlc.User) sqlc.User {
	// TODO: Still returns password = ""
	return sqlc.User{
		Email:             user.Email,
		ID:                user.ID,
		PasswordChangedAt: user.PasswordChangedAt,
		LastLogin:         user.LastLogin,
		CreatedAt:         user.CreatedAt,
	}
}

type LoginUserResponse struct {
	SessionID             uuid.UUID `json:"session_id"`
	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	User                  sqlc.User
}

func CreateUser(config utils.Config, store *sqlc.Store, email string, pwd string) (sqlc.User, string, error) {
	hashedPwd, err := utils.HashPassword(pwd)
	if err != nil {
		return sqlc.User{}, "", err
	}

	uid, err := uuid.NewRandom()
	if err != nil {
		return sqlc.User{}, "", err
	}

	// TODO: Fix null characters
	params := sqlc.CreateUserParams{
		ID: uid,
		Email: sql.NullString{
			String: email,
			Valid:  true,
		},
		PasswordHash: hashedPwd,
	}

	user, err := store.CreateUser(context.Background(), params)
	if err != nil {
		return sqlc.User{}, "", err
	}
	user = newUserResp(user)

	// Create a Paseto token and include user data in the payload
	// Exclude sensitive data like the password
	maker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return sqlc.User{}, "", err
	}

	// Define the payload for the token (excluding the password)
	// payload := token.Payload{
	//     // Include any user-related data you want to store in the token
	//     Username: user.Email,
	// }

	// Create the Paseto token
	pToken, _, err := maker.CreateCustomToken(user, config.AccessTokenDuration) // Set the token expiration as needed
	if err != nil {
		return sqlc.User{}, "", err
	}

	fmt.Println("Token", pToken)

	pUser, _ := verifyToken(config, pToken)
	fmt.Println(pUser.User.ID)
	fmt.Println(pUser.User.Email)

	return user, pToken, nil
}

func verifyToken(config utils.Config, pToken string) (*token.CustomPayload, error) {
	maker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return &token.CustomPayload{}, err
	}

	payload, err2 := maker.VerifyCustomToken(pToken)

	if err2 != nil {
		return &token.CustomPayload{}, err
	}

	return payload, nil
}
